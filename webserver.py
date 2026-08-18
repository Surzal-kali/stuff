from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel
import os
import sys
import asyncio
from pathlib import Path
from typing import List, Optional
import uvicorn

# Import framing.py directly (not via the listeners package, whose __init__
# has an unrelated pre-existing import bug) to avoid triggering it.
sys.path.insert(0, str(Path(__file__).parent / "listeners"))
from listeners.framing import pack_message, read_message

class FrameworkAPI:
    def __init__(self, loader):
        self.loader = loader
        self.app = FastAPI(title="Framework Control Panel")
        self.BRAIN_SOCKET = "/tmp/brain.sock"
        self._setup_routes()

    def _setup_routes(self):
        # --- 1. Dynamic Module Discovery ---
        @self.app.get("/modules")
        async def list_modules():
            """Dynamically list files in the encoders/plugins directory"""
            modules = []
            plugin_path = self.loader.framework_root / "encoders" / "plugins"
            if plugin_path.exists():
                for item in plugin_path.iterdir():
                    modules.append({
                        "name": item.name, 
                        "type": "plugin" if item.is_file() else "folder", 
                        "path": str(item.relative_to(self.loader.framework_root))
                    })
            return modules


        @self.app.post("/auxiliaries/smb_scan")
        async def trigger_smb_scan(targets: List[str]):
            from auxiliaries.smb_scanner import run_smb_recon
            asyncio.create_task(run_smb_recon(targets))
            return {"status": "scanning", "targets": targets}

        @self.app.post("/modules/reload")
        async def reload_module(module_name: str):
            """Actually calls the loader's reload logic"""
            # This assumes the module is already imported in the loader's context
            # In a real scenario, we'd use importlib.import_module(module_name)
            import importlib
            try:
                mod = importlib.import_module(module_name)
                self.loader.reload_module(mod)
                return {"status": "success", "module": module_name}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        # --- 2. Live Process Status ---
        @self.app.get("/status")
        async def get_status():
            """Check if the Unix socket exists and tasks are scheduled"""
            return {
                "brain_active": os.path.exists(self.BRAIN_SOCKET),
                "active_tasks_count": len(self.loader.active_tasks),
                "loader_running": self.loader.runner.thread.is_alive()
            }

        # --- 3. Brain Integration ---
        @self.app.post("/sessions/{session_id}/inject")
        async def inject_session(session_id: str, payload: str):
            """Pipes directly into the Brain sidecar socket"""
            try:
                reader, writer = await asyncio.open_unix_connection(path=self.BRAIN_SOCKET)
                # Using your established triplet format: event|session_id|data
                msg = f"inject|{session_id}|{payload}"
                writer.write(pack_message(msg.encode()))
                await writer.drain()

                response = await read_message(reader)
                writer.close()
                await writer.wait_closed()
                return {"status": "success", "response": response.decode()}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Brain Error: {e}")

    def run(self, host="0.0.0.0", port=8000):
        uvicorn.run(self.app, host=host, port=port)
