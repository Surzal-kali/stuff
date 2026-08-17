import asyncio
import os
import socket
import ctypes

EVENT_HANDLERS = {}

class FrameworkEvent(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_char * 32),
        ("session_id", ctypes.c_int),
        ("data", ctypes.c_char * 1024),
        ("data_len", ctypes.c_size_t),
    ]

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(SCRIPT_DIR, "plugins", "frameit.so")

lib = ctypes.CDLL(LIB_PATH)
socket_path = "/tmp/brain.sock"

# Tell ctypes the C signature: void send_event(const FrameworkEvent *event);
lib.send_event.argtypes = [ctypes.POINTER(FrameworkEvent)]
lib.send_event.restype = None

if os.path.exists(socket_path):
    os.remove(socket_path)

async def start_brain():
    async def handle_client(reader, writer):
        data = await reader.read(1024)
        message = data.decode()
        
        # Parse the event triplet: "event|session_id|data"
        try:
            event_type, session_id, payload = message.split('|', 2)
            session_id = int(session_id)
        except ValueError:
            print(f"Malformed event received: {message}")
            writer.write(b"Error: Malformed event")
            await writer.drain()
            writer.close()
            return

        print(f"Received {event_type} for session {session_id}: {payload}")
        
        # Create the event struct
        event = FrameworkEvent()
        event.event_type = event_type.encode()[:31]
        event.session_id = session_id
        event.data = payload.encode()[:1023]
        event.data_len = len(payload)
        
        await dispatch(event)
        writer.write(b"Event dispatched.")
        await writer.drain()
        writer.close()
    server = await asyncio.start_unix_server(handle_client, path=socket_path)
    async with server:
        await server.serve_forever()

async def dispatch(event):
    event_type = event.event_type.decode().strip('\x00')
    handler = EVENT_HANDLERS.get(event_type)
    
    if handler:
        await handler(event)
    else:
        # Default: forward to the C library if no Python handler is found
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, lib.send_event, ctypes.byref(event))


