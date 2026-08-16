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

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)

class BrainListener:
    def __init__(self, socket_path="/tmp/brain.sock"):
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        self.server.bind(self.socket_path)
        self.server.listen(1)

    def start(self):
        print(f"Listening on {self.socket_path}...")
        while True:
            conn, _ = self.server.accept()
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received command: {data.decode()}")
            lib.send_command(data)
            conn.sendall(b"Command sent to C library.")
            conn.close()


#hear me out, a webfront :D lil ts, lil python. it'll be pretty!
# [ ] Look into a web front-end. 


async def start_brain():
    async def handle_client(reader, writer):
        data = await reader.read(1024)
        message = data.decode()
        print(f"Received command: {message}")
        lib.send_command(message.encode())
        writer.write(b"Command sent to C library.")
        await writer.drain()
        writer.close()
    server = await asyncio.start_unix_server(handle_client, path=socket_path)
    async with server:
        await server.serve_forever()


