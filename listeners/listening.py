from logging.config import listen
import re
import sys
import os
import asyncio
import socket
from asyncio import StreamReader, StreamWriter
import argparse

from framing import pack_message

class TCPListener:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.brain_socket = "/tmp/brain.sock"

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

    async def listen(self, host, port):
        # start_server is the async equivalent of socket.bind + listen + accept
        server = await asyncio.start_server(self.handle_client, host, port)

        addr = server.sockets[0].getsockname()
        print(f"[*] Listening on {addr}... Press Ctrl+C to stop.")

        async with server:
            await server.serve_forever()
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
                self.listen(args.host, args.port),
                self.background_task()
            )
        except KeyboardInterrupt:
            print("\n[!] Shutting down listener...")

if __name__ == "__main__":
    listener = TCPListener()  # Replace with the actual class name
    import asyncio, argparse
    from asyncio import StreamReader, StreamWriter
    asyncio.run(listener.main())