import asyncio
import os
import socket
import ctypes

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(SCRIPT_DIR, "plugins", "frameit.so")

lib = ctypes.CDLL(LIB_PATH)
socket_path = "/tmp/brain.sock"

# Tell ctypes the C signature: void send_command(const char *command);
lib.send_command.argtypes = [ctypes.c_char_p]
lib.send_command.restype = None

if os.path.exists(socket_path):
    os.remove(socket_path)

async def start_brain():
    async def handle_client(reader, writer):
        data = await reader.read(1024)
        message = data.decode()
        print(f"Received command: {message}")
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, lib.send_command, message.encode())
        writer.write(b"Command sent to C library.")
        await writer.drain()
        writer.close()
    server = await asyncio.start_unix_server(handle_client, path=socket_path)
    async with server:
        await server.serve_forever()


