import sys
import code
import asyncio
import threading
import importlib
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).parent

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

class FrameworkLoader:
    def __init__(self, framework_root: Path):
        self.framework_root = framework_root
        self.runner = AsyncBackgroundRunner()
        self.active_tasks = []

    async def start_brain_server(self):
        """Imports and starts the Brain listener."""
        try:
            from listeners.thebrain import start_brain
            print("[+] Starting Brain listener...")
            await start_brain()
        except Exception as e:
            print(f"[!] Brain server failed: {e}")

    async def start_ssl_server(self, ip="0.0.0.0", port=4433):
        """Starts the SSL server binary as a subprocess."""
        ssl_server_path = self.framework_root / "utils" / "plugins" / "ssl_server" / "ssl_server"
        if not ssl_server_path.exists():
            print(f"[!] SSL server binary not found at {ssl_server_path}")
            return

        try:
            print(f"[+] Starting SSL server on {ip}:{port}...")
            process = await asyncio.create_subprocess_exec(
                str(ssl_server_path), ip, str(port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
        except Exception as e:
            print(f"[!] SSL server exception: {e}")

    def launch_all(self):
        """Launches all servers in the background."""
        self.active_tasks.append(self.runner.run_task(self.start_brain_server()))
        self.active_tasks.append(self.runner.run_task(self.start_ssl_server()))
        print("[*] Background servers initialized.")

    def start_shell(self):
        """Starts the interactive Python shell."""
        print("\n--- Modular Security Framework Shell ---")
        print("Type 'exit()' to quit.\n")
        
        local_vars = {
            "loader": self,
            "root": self.framework_root,
            "asyncio": asyncio
        }
        code.interact(banner="Framework Interactive Shell", local=local_vars)

if __name__ == "__main__":
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    try:
        loader.launch_all()
        loader.start_shell()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        loader.runner.stop()
