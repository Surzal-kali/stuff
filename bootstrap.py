import logging
import os
import sys
import asyncio
import threading
import importlib
import signal
from pathlib import Path
from typing import Dict, Optional, List, Any
import socket
import time
from daharness import _chat, ToolRegistry, OllamaEmbeddingFunction
# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- Configuration ---
FRAMEWORK_ROOT = Path(__file__).parent
MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "http://localhost:55552").rstrip("/")
MCP_STARTUP_DELAY = float(os.getenv("MCP_STARTUP_DELAY", "5"))
MCP_STARTUP_TIMEOUT = float(os.getenv("MCP_STARTUP_TIMEOUT", "60"))
MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55552"))

# --- Async Background Runner ---
class AsyncBackgroundRunner:
    """Runs an asyncio event loop in a separate background thread."""
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_task(self, coro):
        """Schedules a coroutine to run in the background loop."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join()

# --- FrameworkLoader ---
class FrameworkLoader:
    def __init__(self, framework_root: Path):
        self.framework_root = framework_root
        self.runner = AsyncBackgroundRunner()
        self.active_tasks: List[Any] = []
        self.tool_registry: Dict[str, tuple] = {}
        self.packet_tool = None
        self.vector_registry = None

        # Initialize ToolRegistry
        try:
            from daharness import ToolRegistry, OllamaEmbeddingFunction
            self.vector_registry = ToolRegistry(
                embedding_model=OllamaEmbeddingFunction(),
                rpc_servers={"metasploit": MCP_ENDPOINT}
            )
            logger.info("[+] Tool vector registry initialized.")
        except Exception as exc:
            logger.error("[!] Tool vector registry failed: %s", exc, exc_info=True)

        # Initialize PacketCraft
        try:
            from utils.packetcraft import PacketCraft
            self.packet_tool = PacketCraft()
        except Exception as exc:
            logger.warning("[!] PacketCraft unavailable: %s", exc)

    async def _wait_for_rpc_port(self, host: str = "127.0.0.1", port: int = 55552, timeout: float = 30.0) -> bool:
        """Wait for the RPC port to become available."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.create_connection((host, port), timeout=1):
                    logger.info("[+] RPC port %s:%s is now open.", host, port)
                    return True
            except (ConnectionRefusedError, socket.timeout):
                await asyncio.sleep(1)
                continue
        logger.warning("[!] RPC port %s:%s did not become available within %s seconds.", host, port, timeout)
        return False


    async def start_metasploit_mcp(self):
        """Starts Metasploit console and handles RPC discovery with retries."""
        try:
            logger.info("[+] Starting Metasploit console for RPC discovery...")
            from payloads.metasploiting import MetasploitClient
            metasploit_client = MetasploitClient()
            process = await metasploit_client.start_mcp()
            if process is None:
                return None

            self.active_tasks.append(process)
            logger.info("[+] MSF console launched. Waiting for RPC port...")

            # Wait for RPC port to be available
            rpc_ready = await self._wait_for_rpc_port(port=MSF_RPC_PORT)
            if not rpc_ready:
                logger.warning("[!] RPC port not available. Skipping tool discovery.")
                return process
            async def _vectorize_tools():
                try:
                    if not self.vector_registry:
                        return
                    logger.info("[+] Connecting to MSF RPC for tool discovery...")
                    await asyncio.sleep(MCP_STARTUP_DELAY)

                    from pymetasploit3.msfrpc import MsfRpcClient
                    client = MsfRpcClient(
                        password=MSGRPC_PASSWORD,
                        port=MSF_RPC_PORT,
                        ssl=False
                    )
                    logger.info("[+] MSF RPC connection established.")
                    modules = client.modules.search(match="")
                    
                    # modules might be a ModuleManager or a list depending on the version/query
                    module_list = modules if isinstance(modules, list) else getattr(modules, 'modules', [])
                    logger.info("[+] %d modules retrieved from MSF RPC.", len(module_list))

                    total = await self.vector_registry.register_tool(module_list)
                    registered_count = len(total) if isinstance(total, list) else total
                    logger.info("[+] RPC Vectorization complete. %d tools registered.", registered_count)
                except Exception as rpc_exc:
                    logger.error("[!] MSF RPC connection failed: %s", rpc_exc, exc_info=True)

            self.active_tasks.append(asyncio.create_task(_vectorize_tools()))
            return process
        except Exception as e:
            logger.error("[!] Metasploit launch failed: %s", e, exc_info=True)
            return None
    
    async def start_brain_server(self):
        """Starts the Brain listener as a sidecar process."""
        try:
            brain_script = self.framework_root / "listeners" / "thebrain.py"
            if not brain_script.exists():
                logger.error("[!] Brain script not found at %s", brain_script)
                return

            logger.info("[+] Starting Brain sidecar...")
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(brain_script),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.active_tasks.append(process)
        except Exception as e:
            logger.error("[!] Brain sidecar failed to launch: %s", e, exc_info=True)

    async def start_ssl_server(self, ip="0.0.0.0", port=4433):
        """Starts the SSL server binary as a subprocess."""
        ssl_server_path = self.framework_root / "utils" / "plugins" / "sslserver" / "ssl_server"
        if not ssl_server_path.exists():
            logger.error("[!] SSL server binary not found at %s", ssl_server_path)
            return

        try:
            logger.info("[+] Starting SSL server on %s:%s...", ip, port)
            process = await asyncio.create_subprocess_exec(
                str(ssl_server_path), ip, str(port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.active_tasks.append(process)
        except Exception as e:
            logger.error("[!] SSL server exception: %s", e, exc_info=True)

    async def reload_module(self, module):
        """Reloads a given module and updates the tool registry."""
        try:
            importlib.reload(module)
            logger.info("[+] Module %s reloaded successfully.", module.__name__)
            for tool_name, (mod_path, func_name) in self.tool_registry.items():
                if mod_path == module.__name__:
                    self.tool_registry[tool_name] = (module.__name__, func_name)
                    logger.info("[+] Tool registry updated for %s.", tool_name)
        except Exception as e:
            logger.error("[!] Failed to reload module %s: %s", module.__name__, e, exc_info=True)
            raise

    async def start_api_server(self):
        """Starts the API server as an async task."""
        try:
            from api_gateway import run as FrameworkAPI
            await FrameworkAPI(loader=self, host="0.0.0.0", port=6000)
        except Exception as e:
            logger.error("[!] API server failed to start: %s", e, exc_info=True)

    async def stop(self):
        """Stops all background tasks and the event loop."""
        logger.info("[*] Stopping background tasks...")
        for task in self.active_tasks:
            if isinstance(task, asyncio.subprocess.Process):
                try:
                    task.terminate()
                except ProcessLookupError:
                    pass
            else:
                    task.cancel()
        self.runner.stop()
        logger.info("[*] All background tasks stopped.")

    async def launch_all(self):
        """Launches all servers in the background."""
        self.tool_registry.update({
            "smb_scan": ("auxiliaries.smb_scanner", "run_smb_recon"),
            "mcp": ("metasploiting", "start_mcp")
        })

        # Start services
        self.active_tasks.append(asyncio.create_task(self.start_brain_server()))
        self.active_tasks.append(asyncio.create_task(self.start_ssl_server()))
        self.active_tasks.append(asyncio.create_task(self.start_api_server()))
        self.active_tasks.append(asyncio.create_task(self.start_metasploit_mcp()))

        # Blocking: Metasploit RPC
        await self.start_metasploit_mcp()
        logger.info("[+] API Control Panel started on port 6000")
        logger.info("[*] Background servers initialized.")

# --- Main ---
async def run_framework():
    daemon_mode = "--daemon" in sys.argv
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    try:
        await loader.launch_all()
        if daemon_mode:
            shutdown_event = asyncio.Event()
            def request_shutdown(*_):
                shutdown_event.set()
            signal.signal(signal.SIGTERM, request_shutdown)
            signal.signal(signal.SIGINT, request_shutdown)
            await shutdown_event.wait()
        else:
            # Interactive mode (restricted)
            logger.info("[*] Entering interactive mode. Type 'exit' to quit.")
            while True:
                    await _chat(registry=ToolRegistry(embedding_model=OllamaEmbeddingFunction(), rpc_servers={"metasploit": MCP_ENDPOINT}))
                    break
    except Exception as e:
        logger.error("[-] Exception in main: %s", e, exc_info=True)
        try:
            with open("/tmp/framework_error.log", "w") as f:
                f.write(str(e))
        except Exception:
            pass
    finally:
        await loader.stop()

if __name__ == "__main__":
    asyncio.run(run_framework())