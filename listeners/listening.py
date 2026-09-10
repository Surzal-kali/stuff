import asyncio
import argparse
import json
import threading
import time
from asyncio import StreamReader, StreamWriter
from typing import Any, Dict, List, Optional

from listeners.thebrain import pack_message
from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()


# ---------------------------------------------------------------------------
# Read-back data store — the piece that was missing.
# ---------------------------------------------------------------------------

class ListenerDataStore:
    """Thread-safe store of received bytes and live client writers.

    Every chunk received by ``handle_client`` is appended here keyed by
    listener handle + client address.  ``read_listener`` polls it back so
    the Brain (or any caller) can retrieve what arrived on a listener
    *after* the fact — exactly the gap that ``TcpListener`` had before.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        # Map of listener_handle -> { peer_addr_str: StreamWriter }
        self._writers: Dict[str, Dict[str, StreamWriter]] = {}

    # -- received data ------------------------------------------------------

    def add_data(self, handle: str, peer: str, data: bytes) -> None:
        with self._lock:
            self._entries.append({
                "handle": handle,
                "peer": peer,
                "data_hex": data.hex(),
                "data_text": data.decode(errors="replace"),
                "size": len(data),
                "ts": time.time(),
            })

    def poll(
        self, handle: str = "", since: float = 0.0, limit: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return received-data entries, optionally filtered.

        Args:
            handle: If non-empty, only entries from this listener handle.
            since:  Only entries at or after this Unix timestamp.
            limit:  If > 0, return at most the *last* N matching entries.
        """
        with self._lock:
            results = [
                e for e in self._entries
                if (not handle or e["handle"] == handle)
                and e["ts"] >= since
            ]
        if limit > 0:
            results = results[-limit:]
        return results

    def clear(self, handle: str = "") -> int:
        """Remove stored entries. Returns count removed."""
        with self._lock:
            if handle:
                before = len(self._entries)
                self._entries = [e for e in self._entries if e["handle"] != handle]
                return before - len(self._entries)
            else:
                n = len(self._entries)
                self._entries.clear()
                return n

    # -- live client writers (for send_to_listener) ------------------------

    def register_writer(self, handle: str, peer: str, writer: StreamWriter) -> None:
        with self._lock:
            self._writers.setdefault(handle, {})[peer] = writer

    def remove_writer(self, handle: str, peer: str) -> None:
        with self._lock:
            conns = self._writers.get(handle)
            if conns:
                conns.pop(peer, None)
                if not conns:
                    self._writers.pop(handle, None)

    def get_writer(self, handle: str, peer: str = "") -> Optional[StreamWriter]:
        with self._lock:
            conns = self._writers.get(handle)
            if not conns:
                return None
            if peer and peer in conns:
                return conns[peer]
            # No peer specified — return the first (most common case: one client)
            if conns:
                return next(iter(conns.values()))
            return None

    def list_clients(self, handle: str = "") -> Dict[str, List[str]]:
        with self._lock:
            if handle:
                return {handle: list(self._writers.get(handle, {}).keys())}
            return {h: list(c.keys()) for h, c in self._writers.items()}


# Module-level singleton — survives across tool calls within one process.
_data_store = ListenerDataStore()


class TCPListener:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.brain_socket = "/tmp/brain.sock"
        # Handle of this listener's SessionManager entry, so close_listener can
        # find and stop it.  Set by open_listener after registering.
        self._handle = None

    @framework_tool("Send a message to the Brain via the Unix socket.")
    async def send_to_brain(self, event_type, session_id, data):
        try:
            reader, writer = await asyncio.open_unix_connection(self.brain_socket)
            # Send as "event|session_id|data", length-prefixed so thebrain.py
            # can read the exact message even if it's split across TCP frames
            payload = f"{event_type}|{session_id}|{data}"
            writer.write(pack_message(payload.encode()))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[!] Failed to send event to brain: {e}")

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addr = server.sockets[0].getsockname()
        print(f"[*] Listening on {addr}... Press Ctrl+C to stop.")

        async with server:
            await server.serve_forever()
            
    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        addr = writer.get_extra_info('peername')
        peer_str = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        session_id = hash(addr) & 0xFFFFFFFF
        print(f"\n[+] New Session established: {addr} (ID: {session_id})")

        # Register this client's writer so send_to_listener can reach it,
        # and so read_listener can report which peers are connected.
        handle = getattr(self, "_handle", None) or ""
        _data_store.register_writer(handle, peer_str, writer)

        await self.send_to_brain("session_start", session_id, f"Connection from {addr}")

        # This creates a persistent session loop for each client
        try:
            while True:
                    data = await reader.read(4096)
                    if not data:
                        break

                    # Store raw received bytes for read-back — the core fix.
                    _data_store.add_data(handle, peer_str, data)

                    message = data.decode(errors="replace").strip()
                    print(f"[{addr}] Received: {message}")

                    await self.send_to_brain("data_received", session_id, message)

                    # Echo back so basic clients get a response. For reverse
                    # shells you typically want to use send_to_listener to
                    # drive the session instead of this auto-echo.
                    response = f"Session {session_id} acknowledged: {message}\n"
                    writer.write(response.encode())
                    await writer.drain()

        except ConnectionResetError:
            print(f"[-] Session {addr} forcibly closed by remote host.")
        except Exception as e:
            print(f"[!] Error in session {addr}: {e}")
        finally:
            _data_store.remove_writer(handle, peer_str)
            await self.send_to_brain("session_end", session_id, f"Closing {addr}")
            print(f"[*] Closing session {addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass  # peer already gone — nothing to close

    @framework_tool(
        "Open (bind) a TCP listener on host:port that waits for inbound "
        "connections. A *listener* is something YOU bind locally to RECEIVE a "
        "callback — e.g. for a reverse shell payload that connects back to "
        "you. This is different from a *backdoor* on the target: a backdoor is "
        "already running there and you pop it via a Metasploit exploit module "
        "(which returns an 'msf:' handle) — you do NOT bind a listener for "
        "that. open_listener returns immediately with a 'listener:' handle; "
        "the listener serves in the background. Use close_listener with the "
        "handle to stop it. Use list_sessions to see active listeners."
    )
    async def open_listener(self, host, port):
        """Bind a TCP listener and register it as a typed session.

        Returns immediately (does not block) with a 'listener:' handle.
        The listener keeps serving in the background.

        Args:
            host: Interface to bind on (e.g. '0.0.0.0').
            port: TCP port to listen on.
        """
        # start_server is the async equivalent of socket.bind + listen + accept
        server = await asyncio.start_server(self.handle_client, host, port)

        addr = server.sockets[0].getsockname()
        print(f"[*] Listening on {addr}... Press Ctrl+C to stop.")

        # A listener is a *service*, not a computation: serve_forever() never
        # returns, so awaiting it here would hang whichever loop called this
        # tool (the Brain's CALL_TOOL handler replies only after the tool
        # returns, and the harness awaits that reply with no timeout). Bind
        # here, hand serving off to a background task, and report back.
        self._server_task = asyncio.create_task(server.serve_forever())
        self._server = server
        self.host, self.port = addr[0], addr[1]

        # Register in the SessionManager so list_sessions shows it and
        # close_listener can find/stop it by handle (Layer 3).  Storing the
        # server object lets close_listener cancel the serve task and close
        # the listening socket.
        sid = _sm.register(
            "listener",
            f"{addr[0]}:{addr[1]}",
            server,
            host=addr[0],
            port=addr[1],
        )
        self._handle = format_handle("listener", sid)
        return (
            f"Listener started on {addr[0]}:{addr[1]} (handle: {self._handle}). "
            "It is serving in the background and will receive inbound "
            "connections. Use close_listener with this handle to stop it, "
            "or list_sessions to see it alongside other sessions."
        )

    @framework_tool(
        "Stop and remove a background TCP listener that was started by "
        "open_listener. Pass the 'listener:' handle returned by open_listener.",
        accepted_handle_kinds=["listener"],
    )
    async def close_listener(self, handle):
        """Stop a bound listener and remove its session entry.

        Args:
            handle: The 'listener:' handle returned by open_listener.
        """
        kind, sid = parse_handle(handle)
        session = _sm.get(sid)
        if session is None:
            return f"Listener {handle} not found. Use list_sessions to see active listeners."
        server = session.client
        # Cancel the serve_forever task and close the listening socket.
        task = getattr(self, "_server_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._server_task = None
        try:
            server.close()
            await server.wait_closed()
        except Exception:
            pass
        _sm.close(sid)
        if getattr(self, "_handle", None) == handle:
            self._handle = None
        # Purge stored data for this listener so it doesn't leak.
        _data_store.clear(handle)
        return f"Listener {handle} stopped."

    # ------------------------------------------------------------------
    # Read-back tools — the core addition that was missing.
    # ------------------------------------------------------------------

    @framework_tool(
        "Read back data received on a TCP listener. Returns a JSON list of "
        "entries, each with {handle, peer, data_text, data_hex, size, ts}. "
        "Pass the 'listener:' handle from open_listener to filter to one "
        "listener, or omit it to get data from ALL listeners. Use 'since' "
        "(Unix timestamp) to get only data after a point in time — typical "
        "usage: call read_listener, note the latest ts, send a command via "
        "send_to_listener, then read_listener again with since=last_ts to "
        "see only the new output. Use 'limit' to cap the number of entries "
        "returned (last N). Use clear_listener_data to wipe the buffer.",
        accepted_handle_kinds=["listener"],
        next_hints=["send_to_listener"],
    )
    def read_listener(self, handle: str = "", since: float = 0.0, limit: int = 0):
        """Retrieve data received by a listener (or all listeners).

        Args:
            handle: 'listener:' handle to filter, or empty for all listeners.
            since:  Only entries at or after this Unix timestamp (0 = all).
            limit:  If > 0, return at most the last N matching entries.
        """
        entries = _data_store.poll(handle=handle, since=since, limit=limit)
        clients = _data_store.list_clients(handle=handle) if handle else _data_store.list_clients()
        result = {
            "entries": entries,
            "connected_clients": clients,
            "total_entries": len(entries),
        }
        return json.dumps(result, indent=2)

    @framework_tool(
        "Send data to a client connected to a TCP listener. This is how you "
        "interact with a reverse shell: open_listener, wait for a callback, "
        "then send_to_listener with a command (e.g. 'id\\n'). Read the "
        "response with read_listener. If 'peer' is omitted and only one "
        "client is connected, it targets that client automatically. The data "
        "is sent as-is (no trailing newline added — include \\n yourself if "
        "the client expects it). Returns the number of bytes written or an "
        "error if no client is connected.",
        accepted_handle_kinds=["listener"],
        next_hints=["read_listener"],
    )
    async def send_to_listener(self, handle: str, data: str, peer: str = ""):
        """Send data to a connected client on a listener.

        Args:
            handle: The 'listener:' handle from open_listener.
            data:   String to send to the client (sent as UTF-8 bytes).
            peer:   Optional 'ip:port' of the specific client. If omitted,
                    targets the first (or only) connected client.
        """
        writer = _data_store.get_writer(handle, peer)
        if writer is None:
            clients = _data_store.list_clients(handle)
            return (
                f"No connected client found on {handle}"
                + (f" for peer {peer}" if peer else "")
                + f". Connected clients: {clients}"
            )
        try:
            payload = data.encode()
            writer.write(payload)
            await writer.drain()
            return f"Sent {len(payload)} bytes to {peer or 'client'} on {handle}."
        except Exception as e:
            return f"Failed to send to {handle}: {e}"

    @framework_tool(
        "Clear stored received-data entries for a listener (or all "
        "listeners). Useful to reset the readback buffer after you've "
        "consumed the output. Returns the number of entries removed.",
        accepted_handle_kinds=["listener"],
    )
    def clear_listener_data(self, handle: str = ""):
        """Clear the readback buffer for a listener or all listeners.

        Args:
            handle: 'listener:' handle, or empty to clear ALL listeners.
        """
        n = _data_store.clear(handle)
        return f"Cleared {n} stored data entries{' for ' + handle if handle else ''}."

    async def stop(self):
        """Stop the background listener started by ``open_listener``, if any
        (instance-level helper, not a framework tool)."""
        task = getattr(self, "_server_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._server_task = None
            return "Listener stopped."
        return "No background listener running."
    async def background_task(self):
        while True:
            await asyncio.sleep(1)
            print("Background task running")

    async def main(self):
        parser = argparse.ArgumentParser(description="Multi-Client TCP Listener")
        parser.add_argument("port", type=int, help="Port to listen on")
        parser.add_argument("--host", default="0.0.0.0", help="Host to connect to")
        # buffer_size is handled inside handle_session read()
        args = parser.parse_args()

        # Run the listener and the background task concurrently
        try:
            await asyncio.gather(
                self.open_listener(args.host, args.port),
                self.background_task()
            )
        except KeyboardInterrupt:
            print("\n[!] Shutting down listener...")
        except Exception as e:
            print(f"[!] Listener encountered an error: {e}")
if __name__ == "__main__":
    listener = TCPListener()  # Replace with the actual class name
    import asyncio, argparse
    from asyncio import StreamReader, StreamWriter
    asyncio.run(listener.main())