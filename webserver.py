from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import socket
import asyncio

app = FastAPI(title="Framework Control Panel")
BRAIN_SOCKET = "/tmp/brain.sock"

# [ ]TODO: Implement a more robust logging system, possibly with log rotation and different log levels, and change the endpoints after we're done with everything else. 
# --- Models ---
class CommandRequest(BaseModel):
    command: str
    args: list = []


class SystemStatus(BaseModel):
    brain_active: bool
    ssl_active: bool
    tcp_active: bool


# --- Helper ---
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


@app.get("/status", response_model=SystemStatus)
async def get_status():
    """Check if the core components are actually running"""
    # You can check if the socket exists and if the SSL binary is in the process list
    import os

    return {
        "brain_active": os.path.exists(BRAIN_SOCKET),
        "ssl_active": True,  # Implement process check here
        "tcp_active": True,  # Implement process check here
    }


@app.post("/execute")
async def execute_command(req: CommandRequest):
    """The primary bridge to the Brain"""
    # Format the command for the C library (e.g., "cmd arg1 arg2")
    full_command = f"{req.command} {' '.join(req.args)}"
    result = await send_to_brain(full_command)
    return {"status": "success", "response": result}


@app.get("/logs")
async def get_logs():
    """Fetch recent activity from your log files"""
    # Simple tail -n 100 of your framework log
    with open("framework.log", "r") as f:
        return {"logs": f.readlines()[-100:]}
