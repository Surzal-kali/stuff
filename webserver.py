from fastapi import FastAPI, HTTPException, Security, WebSocket, Depends
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import os
import sys
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
import uvicorn
from dotenv import load_dotenv
from fastapi_mcp import FastApiMCP
import importlib
COMPILERS = {".c": "gcc", ".cpp": "g++", ".cc": "g++", ".cxx": "g++"}

class CompileRequest(BaseModel):
    source_path: str
    source: Optional[str] = None  # inline content, written to source_path first - lets an AI iterate without a separate file-write step
    mode: str = "plugin"  # "syntax" (check only, no artifact) | "plugin" (.so via -fPIC -shared) | "binary" (standalone executable)
    defines: Optional[Dict[str, str]] = None  # rendered as -DKEY=VALUE, e.g. for listen.cpp's TARGET macro

class LaunchRequest(BaseModel):
    tool_name: str
    args: Optional[List[str]] = None

class SynScanRequest(BaseModel):
    target: str
    port: int
    source_ip: Optional[str] = None
    timeout_ms: int = 250

load_dotenv()

API_KEY = os.getenv("FRAMEWORK_API_KEY")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

if not API_KEY:
    raise RuntimeError("FRAMEWORK_API_KEY must be set (refusing to start with auth disabled)")

async def get_api_key(header_value: str = Security(api_key_header)):
    if header_value and header_value == API_KEY:
        return header_value
    raise HTTPException(status_code=403, detail="Could not validate credentials")
# Import framing.py directly (not via the listeners package, whose __init__
# has an unrelated pre-existing import bug) to avoid triggering it.
sys.path.insert(0, str(Path(__file__).parent / "listeners"))
from listeners.framing import pack_message, read_message

class FrameworkAPI:
    def __init__(self, loader):
        self.loader = loader
        # PacketCraft is owned by the loader and is used by the packet routes.
        # Keep an explicit instance attribute so type checkers and route
        # handlers agree on where the packet tool comes from.
        self.packet_tool = getattr(loader, "packet_tool", None)
        # dependency applied at app-level so every route (and the MCP tools built from them) requires the key
        self.app = FastAPI(title="Framework Control Panel", dependencies=[Depends(get_api_key)])
        self.BRAIN_SOCKET = "/tmp/brain.sock"
        self._setup_routes()
        self._setup_mcp()

    def _setup_routes(self):
        # --- 1. Dynamic Module Discovery ---
        @self.app.get("/modules")
        async def list_modules():
            """Dynamically list files in the auxiliaries directory"""
            modules = []
            plugin_path = self.loader.framework_root / "auxiliaries"
            if plugin_path.exists():
                for item in plugin_path.iterdir():
                    modules.append({
                        "name": item.name, 
                        "type": "plugin" if item.is_file() else "folder", 
                        "path": str(item.relative_to(self.loader.framework_root))
                    })
            return modules

        @self.app.post("/launch")
        async def launch_tool(req: LaunchRequest):
            """Launches a registered Python tool in the background loop."""
            if req.tool_name not in self.loader.tool_registry:
                raise HTTPException(status_code=404, detail=f"Tool '{req.tool_name}' not found in registry")
            
            module_path, func_name = self.loader.tool_registry[req.tool_name]
            
            async def execute():
                try:
                    import importlib
                    mod = importlib.import_module(module_path)
                    func = getattr(mod, func_name)
                    
                    if asyncio.iscoroutinefunction(func):
                        await func(*(req.args or []))
                    else:
                        # Run blocking functions in a thread to avoid hanging the loop
                        await asyncio.get_event_loop().run_in_executor(None, lambda: func(*(req.args or [])))
                    
                    return {"status": "completed"}
                except Exception as e:
                    return JSONResponse(status_code=500, content={"status": "failed", "detail": str(e)})
                    # return {"status": "failed", "error": str(e)}  # Removed redundant return

            # Schedule in background loop and return immediately
            task = self.loader.runner.run_task(execute())
            return {"status": "launched", "tool": req.tool_name, "task_id": id(task)}

        @self.app.post("/compile")
        async def compile_module(req: CompileRequest):
            """Compiles/syntax-checks a C or C++ plugin. Compiling never executes the result - running a
            built artifact stays a separate, deliberate step (e.g. the loaders in bootstrap.py)."""
            root = self.loader.framework_root.resolve()
            src = (root / req.source_path).resolve()
            try:
                src.relative_to(root)
            except ValueError:
                raise HTTPException(status_code=400, detail="source_path must stay inside the framework root")
            if "plugins" not in src.parts:
                raise HTTPException(status_code=400, detail="source_path must live under a 'plugins' directory")
            if src.suffix not in COMPILERS:
                raise HTTPException(status_code=400, detail=f"source_path must end in one of {list(COMPILERS)}")

            if req.source is not None:
                src.parent.mkdir(parents=True, exist_ok=True)
                src.write_text(req.source)
            elif not src.is_file():
                raise HTTPException(status_code=400, detail="source file does not exist and no inline source was provided")

            compiler = COMPILERS[src.suffix]
            define_flags = [f"-D{key}={value}" for key, value in (req.defines or {}).items()]

            output_path: Optional[Path]
            if req.mode == "syntax":
                output_path = None
                args = [compiler, "-fsyntax-only", *define_flags, str(src)]
            elif req.mode == "plugin":
                output_path = src.with_suffix(".so")
                args = [compiler, "-fPIC", "-shared", "-O2", *define_flags, "-o", str(output_path), str(src)]
            elif req.mode == "binary":
                output_path = src.with_suffix("")
                args = [compiler, "-O2", *define_flags, "-o", str(output_path), str(src)]
            else:
                raise HTTPException(status_code=400, detail="mode must be one of: syntax, plugin, binary")

            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise HTTPException(status_code=400, detail=stderr.decode(errors="replace"))
            return {
                "status": "success",
                "mode": req.mode,
                "source": str(src.relative_to(root)),
                "output": str(output_path.relative_to(root)) if output_path else None,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
# --- 2. The Packet Bridge ---
        @self.app.post("/packets/send")
        async def send_custom_packet(request: Dict[str, Any]):
            """Generic interface to PacketCraft recipes"""
            if self.packet_tool is None:
                raise HTTPException(status_code=503, detail="PacketCraft is unavailable; packet sending is disabled at startup.")

            recipe = request.get("recipe")
            params = request.get("params", {})
            preview = request.get("preview", False)

            if not recipe:
                raise HTTPException(status_code=400, detail="Missing 'recipe' parameter")

            # Dynamically find the method in PacketCraft
            method = getattr(self.packet_tool, f"craft_{recipe}" if not hasattr(self.packet_tool, recipe) else recipe, None)
            
            if not method or callable(method) == False:
                raise HTTPException(status_code=404, detail=f"Recipe '{recipe}' not found in PacketCraft")

            try:
                # Generate the packet
                packet = method(**params)
                
                if preview:
                    return {"status": "preview", "hex": self.packet_tool.utils.export_packet_hex(packet)}
                
                # Send the packet
                self.packet_tool.send_packet(packet)
                return {"status": "sent", "recipe": recipe}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Packet error: {str(e)}")

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
        # we need a api post to execute the auxiliaries and pythonic scripts available
        @self.app.post("/auxiliaries/execute")
        async def execute_auxiliary(script_name: str, args: dict):
            """Executes an auxiliary script with the given arguments"""
            try:
                module = importlib.import_module(f"auxiliaries.{script_name}")
                if hasattr(module, "main"):
                    result = await module.main(**args)
                    return {"status": "success", "result": result}
                else:
                    raise HTTPException(status_code=400, detail="No main function found in the script")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Execution Error: {e}")

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

        @self.app.post("/scan/syn")
        async def syn_scan_route(req: SynScanRequest):
            try:
                from listeners.raw_scan import syn_scan
                result = syn_scan(
                    target_ip=req.target,
                    port=req.port,
                    source_ip=req.source_ip,
                    timeout_ms=req.timeout_ms,
                )
                return result
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    def _setup_mcp(self):
        """Exposes every REST route above as an MCP tool for model integrations."""
        self.mcp = FastApiMCP(
            self.app,
            name="Framework Control Panel",
            description="Model-facing tools for the Modular Security Framework control panel",
            headers=[API_KEY_NAME],
        )
        self.mcp.mount_http(mount_path="/mcp")

    def run(self, host="0.0.0.0", port=8000):
        uvicorn.run(self.app, host=host, port=port)

    def add_tool(self, tool_name: str, module_path: str, func_name: str):
        """Adds a custom tool to the framework."""
        self.loader.tool_registry[tool_name] = (module_path, func_name)
        self._setup_mcp()

    def add_syn_scan_tool(self):
        """Adds the syn_scan tool to the framework."""
        self.loader.tool_registry["syn_scan"] = ("listeners.raw_scan", "syn_scan")
