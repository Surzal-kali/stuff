"""Out-of-band (OOB) callback listener — a Burp Collaborator analog.

Multi-protocol listener that catches blind SSRF, blind XSS, and other OOB
callbacks.  Three protocols on one host:

  - HTTP  on TCP 80  — logs request path + source IP
  - HTTPS on TCP 443 — same, using the self-signed cert from sslserver
  - DNS   on UDP 53  — answers ALL queries with a fixed IP, logs full QNAME

The payload ID rides in the subdomain: inject ``http://abc123.oob.lab/`` into
a blind SSRF, the vulnerable server does a DNS lookup for ``abc123.oob.lab``,
the DNS listener logs the QNAME, and the HTTP listener catches the subsequent
callback.  ``collab_poll`` returns both events correlated by the ID prefix.

Lab setup: the DNS listener on port 53 means no dnsmasq or /etc/hosts entry
is needed — it IS the resolver for *.oob.lab (and everything else).  For
real-world OOB, delegate a subdomain NS record to your collaborator host
(config, not code).

Requires root for ports 80, 443, and 53.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import ssl
import string
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()

# --- config ------------------------------------------------------------------

_COLLAB_DOMAIN = os.getenv("COLLAB_DOMAIN", "oob.lab")
_CERT_DIR = Path(os.getenv("WORKSPACE_ROOT", ".")) / "utils" / "plugins" / "sslserver"
_HTTP_PORT = int(os.getenv("COLLAB_HTTP_PORT", "80"))
_HTTPS_PORT = int(os.getenv("COLLAB_HTTPS_PORT", "443"))
_DNS_PORT = int(os.getenv("COLLAB_DNS_PORT", "53"))


def _detect_local_ip() -> str:
    """Best-effort detection of the local IP for DNS responses."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# --- minimal DNS parser/builder ----------------------------------------------

def _parse_dns_qname(data: bytes) -> Optional[str]:
    """Extract the QNAME from a DNS query packet (labels → dotted string)."""
    if len(data) < 13:
        return None
    offset = 12  # skip 12-byte header
    labels: List[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length > 63 or offset + 1 + length > len(data):
            return None  # malformed or compression pointer (not in questions)
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels) if labels else None


def _build_dns_response(query: bytes, answer_ip: str) -> bytes:
    """Build a DNS A-record response for the given query."""
    # Header: copy query header, set QR=1 (response), AA=1, ANCOUNT=1
    header = bytearray(query[:12])
    header[2] |= 0x80  # QR
    header[3] |= 0x04  # AA
    header[6] = 0
    header[7] = 1  # ANCOUNT

    # Find the end of the question section
    q_end = 12
    while q_end < len(query) and query[q_end] != 0:
        q_end += query[q_end] + 1
    q_end += 5  # null byte + QTYPE(2) + QCLASS(2)

    # Answer: pointer to QNAME (0xC00C = offset 12), TYPE A, CLASS IN, TTL 60
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
    answer += socket.inet_aton(answer_ip)

    return bytes(header) + query[12:q_end] + answer


# --- callback store ----------------------------------------------------------

class CallbackStore:
    """Thread-safe list of received OOB callbacks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._callbacks: List[Dict[str, Any]] = []

    def add(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._callbacks.append(entry)

    def poll(self, since: float = 0.0) -> List[Dict[str, Any]]:
        with self._lock:
            return [cb for cb in self._callbacks if cb["ts"] >= since]

    def clear(self) -> None:
        with self._lock:
            self._callbacks.clear()


# --- DNS protocol (asyncio DatagramProtocol) ---------------------------------

class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, store: CallbackStore, answer_ip: str):
        self._store = store
        self._answer_ip = answer_ip
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:  # type: ignore[override]
        qname = _parse_dns_qname(data)
        if qname:
            self._store.add({
                "proto": "dns",
                "src_ip": addr[0],
                "qname": qname,
                "ts": time.time(),
            })
        try:
            response = _build_dns_response(data, self._answer_ip)
            if self._transport:
                self._transport.sendto(response, addr)
        except Exception:
            pass  # malformed query — log what we can, don't crash


# --- collaborator listener ---------------------------------------------------

class CollaboratorListener:
    """Multi-protocol OOB callback listener."""

    def __init__(self) -> None:
        self.store = CallbackStore()
        self.local_ip = _detect_local_ip()
        self.domain = _COLLAB_DOMAIN
        self._http_server: Optional[asyncio.base_events.Server] = None
        self._https_server: Optional[asyncio.base_events.Server] = None
        self._dns_transport: Optional[asyncio.DatagramTransport] = None
        self._tasks: List[asyncio.Task] = []
        self._handle: Optional[str] = None

    # -- HTTP / HTTPS handlers ------------------------------------------------

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        proto: str = "http",
    ) -> None:
        addr = writer.get_extra_info("peername")
        try:
            # Read request line + headers (up to 8 KB or connection close)
            data = await asyncio.wait_for(reader.read(8192), timeout=10)
            text = data.decode("ascii", errors="replace")
            lines = text.split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split()
            path = parts[1] if len(parts) > 1 else "/"

            # Capture Host header and User-Agent for identification
            host = ""
            ua = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                elif line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()

            self.store.add({
                "proto": proto,
                "src_ip": addr[0] if addr else "?",
                "path": path,
                "host": host,
                "user_agent": ua,
                "excerpt": request_line[:256],
                "ts": time.time(),
            })

            # Minimal 200 OK
            body = b"OK\n"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            writer.write(resp)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> str:
        """Start HTTP, HTTPS, and DNS servers. Returns a collab: handle."""
        loop = asyncio.get_running_loop()

        # HTTP
        self._http_server = await asyncio.start_server(
            self._handle_http, "0.0.0.0", _HTTP_PORT,
        )

        # HTTPS (reuse sslserver certs)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = _CERT_DIR / "cert.pem"
        key = _CERT_DIR / "key.pem"
        if cert.is_file() and key.is_file():
            ssl_ctx.load_cert_chain(str(cert), str(key))
            self._https_server = await asyncio.start_server(
                lambda r, w: self._handle_http(r, w, proto="https"),
                "0.0.0.0", _HTTPS_PORT,
                ssl=ssl_ctx,
            )
        # If certs are missing, skip HTTPS (don't crash — HTTP + DNS still work)

        # DNS
        self._dns_transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self.store, self.local_ip),
            local_addr=("0.0.0.0", _DNS_PORT),
        )

        # Background serve tasks
        self._tasks.append(asyncio.create_task(self._http_server.serve_forever()))
        if self._https_server:
            self._tasks.append(asyncio.create_task(self._https_server.serve_forever()))

        # Register in SessionManager
        sid = _sm.register(
            "collab",
            f"{self.local_ip} (http:{_HTTP_PORT} https:{_HTTPS_PORT} dns:{_DNS_PORT})",
            self,
            domain=self.domain,
            ip=self.local_ip,
        )
        self._handle = format_handle("collab", sid)
        return self._handle

    async def stop(self) -> str:
        """Stop all servers and clean up."""
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
        if self._https_server:
            self._https_server.close()
            await self._https_server.wait_closed()
        if self._dns_transport:
            self._dns_transport.close()

        if self._handle:
            kind, sid = parse_handle(self._handle)
            _sm.close(sid)
            self._handle = None
        return "Collaborator stopped."

    def generate(self) -> Dict[str, str]:
        """Generate a unique callback ID and return {id, url, dns_name}."""
        cid = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        dns_name = f"{cid}.{self.domain}"
        return {
            "id": cid,
            "url": f"http://{dns_name}/",
            "dns_name": dns_name,
        }


# --- module-level singleton --------------------------------------------------

_collab: Optional[CollaboratorListener] = None


def _get_collab() -> CollaboratorListener:
    global _collab
    if _collab is None:
        raise RuntimeError(
            "Collaborator not started. Use collab_start first."
        )
    return _collab


# --- framework tools ---------------------------------------------------------

@framework_tool(
    "Start the OOB collaborator listener (HTTP on 80, HTTPS on 443, DNS on "
    "UDP 53). Requires root. Once started, use collab_generate to get unique "
    "callback URLs/DNS names to inject into blind SSRF/XSS payloads, and "
    "collab_poll to check for received callbacks. Returns a 'collab:' handle. "
    "The listener runs in the background — use collab_stop to stop it.",
    next_hints=["collab_generate"],
)
async def collab_start():
    """Start the multi-protocol OOB collaborator listener.

    Returns a 'collab:' handle. Servers run as background asyncio tasks.
    """
    global _collab
    if _collab is not None and _collab._handle is not None:
        return (
            f"Collaborator already running (handle: {_collab._handle}). "
            "Use collab_generate for callback URLs, collab_poll to check results."
        )
    _collab = CollaboratorListener()
    handle = await _collab.start()
    return (
        f"Collaborator started on {_collab.local_ip} "
        f"(http:{_HTTP_PORT} https:{_HTTPS_PORT} dns:{_DNS_PORT}). "
        f"Handle: {handle}. Domain: {_collab.domain}. "
        "Use collab_generate to get callback URLs to inject."
    )


@framework_tool(
    "Generate a unique OOB callback URL and DNS name for injecting into blind "
    "SSF/XSS payloads. Returns {id, url, dns_name}. The id rides in the "
    "subdomain — when the target resolves the DNS name, the collaborator "
    "logs the full qname so you can correlate the callback to this payload. "
    "Example: inject the url into a blind SSRF, then collab_poll to see the "
    "DNS + HTTP callback.",
    next_hints=["collab_poll"],
)
def collab_generate():
    """Generate a unique callback ID, URL, and DNS name."""
    c = _get_collab()
    result = c.generate()
    return json.dumps(result)


@framework_tool(
    "Poll the collaborator for received OOB callbacks since a timestamp. "
    "Returns a list of {proto, src_ip, qname/path, ts, excerpt}. proto is "
    "'dns', 'http', or 'https'. If since is omitted or 0, returns ALL "
    "callbacks. Use the id from collab_generate to filter — the id appears "
    "in the qname (for DNS) or the Host header (for HTTP/HTTPS).",
    next_hints=["report_finding"],
)
def collab_poll(since: float = 0.0):
    """Poll for OOB callbacks received since the given Unix timestamp.

    Args:
        since: Unix timestamp (float). Only callbacks at or after this time
               are returned. 0 = all callbacks.
    """
    c = _get_collab()
    callbacks = c.store.poll(since)
    return json.dumps(callbacks, indent=2)


@framework_tool(
    "Stop the OOB collaborator listener and free its ports. Pass the "
    "'collab:' handle returned by collab_start.",
    accepted_handle_kinds=["collab"],
)
async def collab_stop(handle: str = ""):
    """Stop the collaborator listener.

    Args:
        handle: The 'collab:' handle from collab_start (optional — if omitted,
                stops the current singleton).
    """
    global _collab
    if _collab is None:
        return "Collaborator not running."
    msg = await _collab.stop()
    _collab = None
    return msg
