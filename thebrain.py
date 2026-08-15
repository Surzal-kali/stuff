import os
import socket

socket_path="/tmp/brain.sock"

if os.path.exists(socket_path):
    os.remove(socket_path)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)

#kay so we're looking at IPC, between js, cpp, and python being the orchestrator, abusing sockets to facilitate communication. 

#Problem: javascript and cpp could read from the stream not all the way through, so it'll get (cmd: who-) and then nothing happens and shits brokie. SO. we have to have a prefix in the stream for each command, an int that tells the other side how many bytes to read. So we can read the prefix, then read the rest of the command.


def prefix_command(command):
    # Prefix the command with its length
    length = len(command)
    return f"{length}:{command}"

def command_loop():
    while True:
        conn, _ = server.accept()
        with conn:
            data = conn.recv(1024)
            if not data:
                break
            # Process the received command
            command = data.decode('utf-8')
            print(f"Received command: {command}")
            # Here you can add logic to handle the command (i have no idea what im doing yet so this is basically a stub AFAIK)


if __name__ == "__main__":
    print("Server is running...")
    command_loop()
    