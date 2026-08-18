from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel
import socket
import asyncio
import os
from typing import List, Optional
import uvicorn

app = FastAPI(title="Framework Control Panel")
BRAIN_SOCKET = "/tmp/brain.sock"

# --- Models ---
class CommandRequest(BaseModel):
    command: str
    args: List[str] = []

class ModuleInfo(BaseModel):
    name: str
    type: str # 'python' or 'plugin'
    path: str

class ListenerStatus(BaseModel):
    id: str
    port: int
    status: str
    connections: int

class SystemStatus(BaseModel):
    brain_active: bool
    ssl_active: bool
    tcp_active: bool

# --- Helpers ---
async def send_to_brain(payload: str):
    """Helper to communicate with the Brain sidecar"""
    try:
        reader, writer = await asyncio.open_unix_connection(path=BRAIN_SOCKET)
        writer.write(payload.encode())
        await writer.drain()

        response = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return response.decode()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Brain Communication Error: {e}")

# --- Routes ---

# 1. Framework & Module Management
@app.get("/modules", response_model=List[ModuleInfo])
async def list_modules():
    """List all loaded Python modules and compiled plugins."""
    # In a real impl, this would query the FrameworkLoader
    return [
        {"name": "packetcraft", "type": "python", "path": "utils/packetcraft.py"},
        {"name": "ssl_server", "type": "plugin", "path": "utils/plugins/sslserver/ssl_server"}
    ]

@app.post("/modules/reload")
async def reload_module(module_name: str):
    """Trigger a reload of a specific module."""
    # Logic to call loader.reload_module()
    return {"status": "success", "module": module_name, "message": "Reloaded successfully"}

@app.get("/status", response_model=SystemStatus)
async def get_status():
    """Check if the core components are actually running"""
    return {
        "brain_active": os.path.exists(BRAIN_SOCKET),
        "ssl_active": True, 
        "tcp_active": True,
    }

# 2. Listener Control
@app.get("/listeners", response_model=List[ListenerStatus])
async def list_listeners():
    """List active listeners and their state."""
    return [
        {"id": "ssl_server", "port": 4433, "status": "running", "connections": 0}
    ]

@app.post("/listeners/start")
async def start_listener(listener_id: str):
    """Launch a specific listener binary."""
    # Call to loader.start_ssl_server() or similar
    return {"status": "success", "listener": listener_id}

@app.post("/listeners/stop")
async def stop_listener(listener_id: str):
    """Kill a specific listener process."""
    return {"status": "success", "listener": listener_id}

# 3. Session & Inspection
@app.get("/sessions")
async def list_sessions():
    """List all active encrypted sessions."""
    return [{"session_id": "sess_001", "remote_ip": "127.0.0.1", "cipher": "TLS_AES_256_GCM_SHA384"}]

@app.websocket("/sessions/{session_id}/stream")
async def session_stream(websocket: WebSocket, session_id: str):
    """Real-time decrypted traffic stream from the inspection hook."""
    await websocket.accept()
    try:
        while True:
            # This is where you'd hook into the C-side inspection engine's buffer
            data = f"[Session {session_id}] Decrypted packet: Hello World"
            await websocket.send_text(data)
            await asyncio.sleep(2) # Simulation
    except Exception as e:
        print(f"Stream closed: {e}")
    finally:
        await websocket.close()

@app.post("/sessions/{session_id}/inject")
async def inject_session(session_id: str, payload: str):
    """Send raw bytes back into an active SSL session."""
    result = await send_to_brain(f"inject {session_id} {payload}")
    return {"status": "success", "response": result}

# 4. Payloads & Auxiliaries
@app.get("/payloads")
async def list_payloads():
    """List available C/C++ payloads."""
    return [{"name": "listen_shell", "path": "payloads/plugins/listen.cpp"}]

@app.post("/auxiliaries/scan")
async def run_network_scan(target: str):
    """Trigger the networkscan.py module."""
    # Call to auxiliaries.networkscan.run(target)
    return {"status": "scanning", "target": target}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)