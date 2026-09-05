import asyncio
import os
import socket
import ctypes
import inspect
import importlib
import functools
import json
import sys
from pathlib import Path
from typing import Dict, Callable, Any, Optional
from enum import Enum
from constants import TransportType
from listeners.framing import pack_message, read_message

EVENT_HANDLERS = {}

def framework_tool(doc: str = None, transport: TransportType = TransportType.BRAIN_DISPATCH):
    """Decorator to mark a function as a framework tool callable by the Brain."""
    def decorator(func):
        func._is_framework_tool = True
        func._tool_doc = doc or (func.__doc__ or "No description provided.")
        func._transport = transport  # <--- The tag!
        return func
    return decorator

class FunctionRegistry:
    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.metadata: Dict[str, Dict] = {}

    def register(self, name: str, func: Callable, doc: str):
        self.tools[name] = func
        self.metadata[name] = {"doc": doc, "args": inspect.signature(func)}

    def get_tool(self, name: str) -> Optional[Callable]:
        return self.tools.get(name)

    def get_metadata(self, name: str) -> Optional[Dict]:
        return self.metadata.get(name)

    def scan_module(self, module):
        for name, obj in inspect.getmembers(module):
            if inspect.isfunction(obj) and getattr(obj, "_is_framework_tool", False):
                tool_id = f"{module.__name__}.{name}"
                self.register(tool_id, obj, getattr(obj, "_tool_doc", ""))
                print(f"[+] Registered framework tool: {tool_id}")

registry = FunctionRegistry()

class FrameworkEvent(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_char * 32),
        ("session_id", ctypes.c_int),
        ("data", ctypes.c_char * 1024),
        ("data_len", ctypes.c_size_t),
    ]

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).resolve().parent
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
        try:
            data = await read_message(reader)
        except (asyncio.IncompleteReadError, ValueError) as e:
            print(f"Dropped connection: {e}")
            writer.close()
            return

        message = data.decode()

        # Parse the event triplet: "event|session_id|data"
        try:
            event_type, session_id, payload = message.split('|', 2)
            session_id = int(session_id)
        except ValueError:
            print(f"Malformed event received: {message}")
            writer.write(pack_message(b"Error: Malformed event"))
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
        
        result = await dispatch(event)
        response = result.encode() if result else b"Event dispatched."
        writer.write(pack_message(response))
        await writer.drain()
        writer.close()
    server = await asyncio.start_unix_server(handle_client, path=socket_path)
    async with server:
        await server.serve_forever()

async def dispatch(event):
    event_type = event.event_type.decode().strip('\x00')
    
    # Handle tool discovery: "SCAN_TOOLS|session_id|path/to/scan"
    if event_type == "SCAN_TOOLS":
        try:
            scan_path = event.data.decode().strip('\x00')
            if not scan_path:
                # Default to framework root if no path provided
                scan_path = SCRIPT_DIR.parent 
            
            path = Path(scan_path)
            found_tools = []
            
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".py") and file != "thebrain.py":
                        module_name = Path(root).relative_to(path).as_posix()
                        if module_name:
                            # Handle package structure
                            module_path = f"{module_name.replace('/', '.')}.{Path(file).stem}"
                        else:
                            module_path = Path(file).stem
                        
                        try:
                            # Import the module dynamically
                            # Ensure the framework root is in sys.path to resolve absolute imports like 'listeners.xxx'
                            root_path = str(path)
                            if root_path not in sys.path:
                                sys.path.insert(0, root_path)
                            
                            mod = importlib.import_module(module_path)
                            registry.scan_module(mod)
                            
                            # Collect metadata for the response
                            for tool_id in registry.tools:
                                if tool_id.startswith(module_path):
                                    found_tools.append(f"{tool_id}:{registry.metadata[tool_id]['doc']}")
                        except Exception as e:
                            print(f"[!] Failed to scan module {module_path}: {e}")
            
            return "SCAN_COMPLETE|" + ",".join(found_tools)
        except Exception as e:
            return f"ERROR: Scan failed: {str(e)}"

    # Handle tool calls via the Brain
    if event_type == "CALL_TOOL":
        try:
            # Expecting data as "tool_id|arg1,arg2..." or JSON
            payload = event.data.decode().strip('\x00')
            if '|' in payload:
                tool_id, args_str = payload.split('|', 1)
                args = args_str.split(',') if args_str else []
            else:
                # Fallback to JSON for complex args
                try:
                    parsed = json.loads(payload)
                    tool_id = parsed.get("tool_id")
                    args = parsed.get("args", [])
                except json.JSONDecodeError:
                    tool_id = payload
                    args = []

            tool = registry.get_tool(tool_id)
            if tool:
                # Execute tool in a thread to avoid blocking the event loop
                loop = asyncio.get_event_loop()
                # Handle both positional and keyword args
                if isinstance(args, dict):
                    result = await loop.run_in_executor(None, functools.partial(tool, **args))
                else:
                    result = await loop.run_in_executor(None, functools.partial(tool, *args))
                
                print(f"[+] Tool {tool_id} executed successfully: {result}")
                return f"SUCCESS: {result}"
            else:
                return f"ERROR: Tool {tool_id} not found in registry."
        except Exception as e:
            return f"ERROR: Execution failed: {str(e)}"

    handler = EVENT_HANDLERS.get(event_type)
    
    if handler:
        await handler(event)
    else:
        # Default: forward to the C library if no Python handler is found
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, lib.send_event, ctypes.byref(event))

if __name__ == "__main__":
    asyncio.run(start_brain())



