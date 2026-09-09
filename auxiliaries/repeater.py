"""Burp Repeater / Intruder analog over the framework's TLS echo server.

The framework ships a TLS echo server (``utils/plugins/sslserver/ssl_server``,
bound to ``0.0.0.0:4433`` by ``bootstrap.start_ssl_server``). It's unused by
any tool today. We repurpose it as a *controlled replay target*:

    - ``ssl_replay``  takes a raw HTTP/1.1 request string (URL, headers, body)
      and fires it at the echo server. The echo server reads our bytes,
      prints them, and writes them straight back -- so the response body
      IS the request body. That round-trip is enough for the model to inspect
      how a given payload is parsed/serialised by the TLS layer (length,
      framing, charset, line endings) and to test tamper-resistant payloads
      in isolation without hitting a real target.
    - ``ssl_intrude`` does the same thing N times after substituting a single
      placeholder token (``§FUZZ§`` by default, Burp-style) against an
      iterable of values. That's the Intruder analog: one position, many
      payloads, side-by-side results.

Both tools loop over ``requests.Session`` with ``verify=False`` (the cert is
self-signed, so verification is a no-op on loopback) and surface status,
headers, body, and a 200-byte preview per attempt. They use the framework's
existing singleton pattern (``RepeaterClient.get_instance()``) so the
``requests.Session`` is reused.

These are deliberately scope-limited. The echo server has no real
application logic -- it's a TLS framing exerciser, not a vulnerable app.
For real fuzzing against a target webapp, use ZAP's active scan instead.
The point of these tools is the *replay/intrude ergonomics* (one tool call
submits many variants and returns a structured result) without standing up
Burp or a second fuzzing harness.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from constants import framework_tool


REPEATER_HOST = "127.0.0.1"   # always loopback; the SSL server is local
REPEATER_PORT = 4433
SSL_BASE = f"https://{REPEATER_HOST}:{REPEATER_PORT}"

# Burp-compatible placeholder token. One position only -- multi-position
# intruder is out of scope for this echo-server analog.
FUZZ_MARKER = "\u00a7FUZZ\u00a7"


class RepeaterClient:
    _instance: Optional["RepeaterClient"] = None

    @classmethod
    def get_instance(cls) -> "RepeaterClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.session = requests.Session()
        # Self-signed cert: skip verification on loopback. Disable env-proxy
        # noise so the test stays hermetic.
        self.session.trust_env = False

    # ---- primitives ------------------------------------------------------

    def _send(self, raw_request: str) -> Dict[str, Any]:
        """Parse ``raw_request`` (must include request line + headers + blank
        line + optional body) and POST it at the echo server.

        The echo server is a TLS echo, not an HTTP parser: it writes back
        whatever it reads. So we get status/headers from ``requests`` based
        on what *we* sent, and the ``body`` field is the same bytes we sent
        (useful for confirming what the wire actually carried).
        """
        # Split request line from headers+body; ``requests`` builds its own
        # request so we don't need to feed it bytes -- we parse minimally
        # just to extract the host (which the SSL server already knows) and
        # the path, then replay through ``requests`` for proper status code
        # handling.
        try:
            head, body = raw_request.split("\r\n\r\n", 1) if "\r\n\r\n" in raw_request \
                else (raw_request.split("\n\n", 1)[0], "")
        except ValueError:
            head, body = raw_request, ""

        lines = head.splitlines()
        if not lines:
            return {"error": "empty request"}
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            return {"error": f"malformed request line: {request_line!r}"}
        method, path = parts[0], parts[1]

        # Build headers
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
        # Host header is required by HTTP/1.1; if the caller didn't supply
        # one, set it to the echo server's loopback address.
        headers.setdefault("Host", f"{REPEATER_HOST}:{REPEATER_PORT}")

        # Build the URL: requests will reuse our path verbatim. The echo
        # server doesn't route by path -- everything goes to /echo -- but
        # preserving the path matters for tools that diff request paths.
        url = SSL_BASE + (path if path.startswith("/") else "/" + path)

        try:
            r = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=body.encode("utf-8", errors="surrogateescape"),
                verify=False,
                timeout=10,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            return {"error": f"transport error: {e}", "method": method, "path": path}

        return {
            "method": method,
            "path": path,
            "status_code": r.status_code,
            "response_headers": dict(r.headers),
            "sent_bytes": len(body.encode("utf-8", errors="surrogateescape")),
            "received_bytes": len(r.content),
            # The echo server mirrors the request body, so this is the same
            # bytes we sent back to us -- a wire-level integrity check.
            "echoed_body_preview": r.content[:200].decode("utf-8", errors="replace"),
        }

    def replay(self, raw_request: str) -> Dict[str, Any]:
        """Send a single raw HTTP request; return one result dict."""
        return self._send(raw_request)

    def intrude(
        self,
        raw_request: str,
        payloads: List[str],
        marker: str = FUZZ_MARKER,
    ) -> List[Dict[str, Any]]:
        """Substitute ``marker`` with each payload and replay. One position,
        N payloads. Returns one result dict per payload (in order)."""
        if marker not in raw_request:
            return [{"error": f"marker {marker!r} not found in request"}]
        results: List[Dict[str, Any]] = []
        for p in payloads:
            variant = raw_request.replace(marker, p)
            res = self._send(variant)
            res["payload"] = p
            results.append(res)
        return results


def _rep() -> RepeaterClient:
    return RepeaterClient.get_instance()


@framework_tool(
    "Replay a single raw HTTP/1.1 request through the framework's local TLS "
    "echo server (Burp Repeater analog). Returns the HTTP response code, headers, and echoed body."
)
def ssl_replay(raw_request):
    """Pass a full request including the request line, headers, blank line,
    and optional body (CRLF line endings). Useful for confirming how a given
    payload traverses TLS framing without hitting a real target."""
    return _rep().replay(raw_request)


@framework_tool(
    "Fuzz one position in a raw HTTP request with N payloads and replay each "
    "variant through the TLS echo server (Burp Intruder analog, single position)."
)
def ssl_intrude(raw_request, payloads, marker=FUZZ_MARKER):
    """Substitute ``marker`` (default ``\u00a7FUZZ\u00a7``) with each entry in
    ``payloads`` and replay every variant. One result dict per payload, in order."""
    return _rep().intrude(raw_request, list(payloads), marker=marker)
