from fastapi import FastAPI, HTTPException, Security, WebSocket, Depends
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import os
import sys
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
import uvicorn
from dotenv import load_dotenv
from fastapi_mcp import FastApiMCP
import importlib
from memories import MemoryService
COMPILERS = {".c": "gcc", ".cpp": "g++", ".cc": "g++", ".cxx": "g++"}

class CompileRequest(BaseModel):
    """Request body for compiling a C/C++ plugin or checking syntax.

    Use this when you want to build a plugin under the framework's plugins tree
    without running it immediately. The route enforces that source_path remains
    under the framework root and that the file lives under a plugins directory.
    """
    source_path: str = Field(..., description="Relative path inside the framework root, usually under a plugins directory, e.g. listeners/plugins/raw_scan.cpp")
    source: Optional[str] = Field(default=None, description="Optional inline source content to write to source_path before compiling")
    mode: str = Field(default="plugin", description="Compilation mode: syntax, plugin, or binary")
    defines: Optional[Dict[str, str]] = Field(default=None, description="Optional preprocessor defines to pass as -DKEY=VALUE flags")

class LaunchRequest(BaseModel):
    """Request body for launching a registered framework tool by name."""
    tool_name: str = Field(..., description="Registered tool name from the framework registry, such as smb_scan")
    args: Optional[List[str]] = Field(default=None, description="Positional arguments to pass to the tool function")

class SynScanRequest(BaseModel):
    """Request body for a raw SYN scan against a target host or IP.

    Note: this path uses raw TCP socket behavior and typically requires root or
    CAP_NET_RAW privileges. It is intended for lab or privileged network testing.
    """
    target: str = Field(..., description="Target IP address to scan, e.g. 192.168.1.10")
    port: int = Field(..., ge=1, le=65535, description="Destination TCP port to probe")
    source_ip: Optional[str] = Field(default=None, description="Optional source IP to use for the scan packet. If omitted, the wrapper may default to a placeholder value.")
    timeout_ms: int = Field(default=250, ge=1, le=5000, description="Socket receive timeout in milliseconds")

class PacketSendRequest(BaseModel):
    """Request body for sending a custom packet using a PacketCraft recipe.

    Use this to emit custom network packets generated from an existing PacketCraft
    method, such as a TCP, UDP, ICMP, DNS, or ARP packet. Supply a recipe name and
    the matching keyword arguments in params. Set preview=true to inspect the packet
    hex without transmitting it.
    """
    recipe: str = Field(..., description="PacketCraft recipe name")
    params: Dict[str, Any] = Field(default_factory=dict, description="Recipe parameters")
    preview: bool = Field(default=False, description="Whether to preview without sending")

class MemorySearchRequest(BaseModel):
    """Request body for searching the framework memory vault."""
    namespace: str = Field(..., description="Memory namespace to search, e.g. intel or sessions")
    query_text: Optional[str] = Field(default=None, description="Text keyword to match within stored documents")
    query_embedding: Optional[List[float]] = Field(default=None, description="Optional embedding to run semantic similarity search")
    session_id: Optional[str] = Field(default=None, description="Optional session identifier to scope the memory search to a single runtime session")
    limit: int = Field(default=5, ge=1, le=25, description="Maximum number of results")

class MemoryRememberRequest(BaseModel):
    """Request body for storing a frame fact in the memory vault."""
    namespace: str = Field(..., description="Namespace to store the memory under")
    memory_id: str = Field(..., description="Stable unique identifier for the memory")
    text: str = Field(..., description="Human-readable content to be stored")
    embedding: List[float] = Field(..., description="Embedding vector for similarity search")
    session_id: Optional[str] = Field(default=None, description="Optional session identifier associated with this memory entry")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional additional metadata")

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
        self.memory = MemoryService(storage_path=str(Path(loader.framework_root) / ".memory" / "chroma"))
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
            """List available auxiliary modules and plugin folders.

            Use this to discover what capabilities are already built into the framework
            before invoking a module or tool. Returns names, types, and relative paths.
            """
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
            """Launch a registered framework tool in the background runner.

            This is the generic execution path for framework capabilities that were
            previously registered in the loader. Use it when you know the tool name and
            want the framework to execute it asynchronously without blocking the API.
            """
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
            """Compile or syntax-check a C/C++ plugin inside the framework tree.

            This route is intended for building and validating native plugin code.
            Use mode='syntax' for a fast compiler check, mode='plugin' to produce a .so,
            or mode='binary' to compile a standalone executable. The source file must be
            under a plugins directory inside the framework root.
            """
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
        async def send_custom_packet(req: PacketSendRequest):
            """Send a crafted packet using a PacketCraft recipe.

            Use this to emit custom network packets generated from an existing PacketCraft
            method, such as a TCP, UDP, ICMP, DNS, or ARP packet. Supply a recipe name and
            the matching keyword arguments in params. Set preview=true to inspect the packet
            hex without transmitting it.
            """
            if self.packet_tool is None:
                raise HTTPException(status_code=503, detail="PacketCraft is unavailable; packet sending is disabled at startup.")

            recipe = req.recipe
            params = req.params
            preview = req.preview

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
            """Run the SMB reconnaissance auxiliary against a list of targets.

            This schedules the SMB scanning routine in the background and returns immediately.
            Use it when you want rapid host enumeration from the framework's auxiliary tooling.
            """
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
            """Return the current framework health summary.

            This is the fastest way to confirm whether the brain socket is active,
            whether background tasks are running, and whether the loader thread is healthy.
            """
            return {
                "brain_active": os.path.exists(self.BRAIN_SOCKET),
                "active_tasks_count": len(self.loader.active_tasks),
                "loader_running": self.loader.runner.thread.is_alive()
            }
        # we need a api post to execute the auxiliaries and pythonic scripts available
        @self.app.post("/auxiliaries/execute")
        async def execute_auxiliary(script_name: str, args: dict):
            """Execute a Python auxiliary module by name.

            Provide the module name without the auxiliaries prefix and pass any keyword
            arguments required by that module's main() function. This is the main entry
            point for model-driven auxiliary execution.
            """
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
            """Inject a payload into a session through the brain sidecar socket.

            Use this when you want to push a command or message directly into an active
            session stream managed by the framework brain. The payload is wrapped in the
            existing message format and sent over the Unix socket path.
            """
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
            """Perform a SYN scan against a target host on a single TCP port.

            This is a privileged raw-socket scan intended for lab or controlled testing.
            It returns a simple status payload, such as open, closed_or_filtered, or error.
            Use it when you need a lightweight port probe without a full port scanner.
            """
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

        @self.app.post("/memory/search")
        async def search_memory(req: MemorySearchRequest):
            """Search the framework memory store by keyword or embedding similarity."""
            if req.query_text is None and req.query_embedding is None:
                raise HTTPException(status_code=400, detail="Either query_text or query_embedding must be provided")

            if req.query_text is not None:
                hits = self.memory.search(
                    namespace=req.namespace,
                    query_text=req.query_text,
                    limit=req.limit,
                    session_id=req.session_id,
                )
                return {"namespace": req.namespace, "query_text": req.query_text, "session_id": req.session_id, "hits": hits}

            if req.query_embedding is not None:
                hits = self.memory.recall(
                    namespace=req.namespace,
                    query_embedding=req.query_embedding,
                    limit=req.limit,
                    session_id=req.session_id,
                )
                return {"namespace": req.namespace, "query_embedding": req.query_embedding, "session_id": req.session_id, "hits": hits}

            return {"namespace": req.namespace, "session_id": req.session_id, "hits": []}

        @self.app.post("/memory/remember")
        async def remember_memory(req: MemoryRememberRequest):
            """Store a memory entry in the framework memory store."""
            payload = dict(req.metadata or {})
            memory_id = self.memory.remember(
                namespace=req.namespace,
                memory_id=req.memory_id,
                text=req.text,
                embedding=req.embedding,
                session_id=req.session_id,
                **payload,
            )
            return {"namespace": req.namespace, "memory_id": memory_id, "session_id": req.session_id, "status": "stored"}

    def _setup_mcp(self):
        """Exposes every REST route above as an MCP tool for model integrations."""
        self.mcp = FastApiMCP(
            self.app,
            name="Framework Control Panel",
            description="Model-facing toolset for the Modular Security Framework. Includes plugin compilation, module discovery, auxiliary execution, packet crafting, session injection, and SYN scanning operations.",
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
