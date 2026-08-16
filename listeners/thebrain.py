import os
import socket
import ctypes

lib=ctypes.CDLL("./frameit.so")
socket_path="/tmp/brain.sock"

# Load the shared library (relative or absolute path)
lib = ctypes.CDLL("./frameit.so")

# Tell ctypes the C signature: void send_command(const char *command);
lib.send_command.argtypes = [ctypes.c_char_p]
lib.send_command.restype = None

if os.path.exists(socket_path):
    os.remove(socket_path)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)

if __name__ == "__main__":
    while True:
        conn, _ = server.accept()
        data = conn.recv(1024)
        if not data:
            break
        print(f"Received command: {data.decode()}")
        lib.send_command(data)
        conn.sendall(b"Command sent to C library.")
        conn.close()


#hear me out, a webfront :D lil ts, lil python. it'll pretty!
# [ ] Look into a web front-end. 