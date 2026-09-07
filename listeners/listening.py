import asyncio
import argparse
from asyncio import StreamReader, StreamWriter

from listeners.thebrain import pack_message
from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()


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
        session_id = hash(addr) & 0xFFFFFFFF
        print(f"\n[+] New Session established: {addr} (ID: {session_id})")
        
        await self.send_to_brain("session_start", session_id, f"Connection from {addr}")

        # This creates a persistent session loop for each client
        try:
            while True:
                    # Use a timeout or a specific signal to break the loop
                    data = await reader.read(1024)
                    if not data: # If no data is received, the connection is closed.
                        break

                    message = data.decode().strip()
                    print(f"[{addr}] Received: {message}")
                    
                    await self.send_to_brain("data_received", session_id, message)

                    # Echo back or send command (Example: basic interaction)
                    response = f"Session {session_id} acknowledged: {message}\n"
                    writer.write(response.encode())
                    await writer.drain()
                    

        except ConnectionResetError:
            print(f"[-] Session {addr} forcibly closed by remote host.")
        except Exception as e:
            print(f"[!] Error in session {addr}: {e}")
        finally:
            await self.send_to_brain("session_end", session_id, f"Closing {addr}")
            print(f"[*] Closing session {addr}")
            writer.close()
            await writer.wait_closed()

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
        return f"Listener {handle} stopped."

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