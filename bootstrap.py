import sys
import code
import asyncio
import threading
import importlib
from pathlib import Path
from webserver import FrameworkAPI
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
        """Starts the Brain listener as a separate sidecar process."""
        try:
            import subprocess
            brain_script = self.framework_root / "listeners" / "thebrain.py"
            if not brain_script.exists():
                print(f"[!] Brain script not found at {brain_script}")
                return

            print("[+] Starting Brain sidecar...")
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(brain_script),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # We let it run as a sidecar process in the background
        except Exception as e:
            print(f"[!] Brain sidecar failed to launch: {e}")

    async def start_ssl_server(self, ip="0.0.0.0", port=4433):
        """Starts the SSL server binary as a subprocess."""
        ssl_server_path = self.framework_root / "utils" / "plugins" / "sslserver" / "ssl_server"
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
        self.api = FrameworkAPI(self)
        self.api_thread = threading.Thread(target=self.api.run, kwargs={"host": "0.0.0.0", "port": 8000}, daemon=True)
        self.api_thread.start()
        print("[+] API Control Panel started on port 8000")
        print("[*] Background servers initialized.")

    def stop(self):
        """Stops all background tasks and the event loop."""
        print("[*] Stopping background tasks...")
        for task in self.active_tasks:
            task.cancel()
        self.runner.stop()
        print("[*] All background tasks stopped.")



    def reload_module(self, module):
        """Reloads a previously imported module."""
        try:
            importlib.reload(module)
            print(f"[+] Successfully reloaded {module.__name__}")
        except Exception as e:
            print(f"[-] Failed to reload {module.__name__}: {e}")

if __name__ == "__main__":
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    try:
        loader.launch_all()
        while True:
            user_input = input(">>> ")
            if user_input.strip() == "exit":
                break
            elif user_input.startswith("reload "):
                module_name = user_input.split(" ", 1)[1].strip()
                try:
                    module = importlib.import_module(module_name)
                    loader.reload_module(module)
                except ModuleNotFoundError:
                    print(f"[-] Module {module_name} not found.")
            else:
                try:
                    exec(user_input, globals())
                except Exception as e:
                    print(f"[-] Error executing command: {e}")
    except Exception as e:
        print(f"[-] Exception in main: {e}")
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        loader.stop()
