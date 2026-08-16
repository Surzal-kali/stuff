import sys
import code
import tempfile
import shlex
import importlib
import importlib.util
from pathlib import Path
import asyncio
import concurrent.futures

FRAMEWORK_ROOT = Path(__file__).parent
#[ ]TODO: rewrite
class FrameworkLoader:
    """
    Checks for child "strap" python submodules to properly load the underlying c++ binaries/ python modules
    """
    def __init__(self, framework_root: Path):
        self.framework_root = framework_root
        self.loaded_modules = {}
        self.loaded_binaries = {}
        self.loaded_paths = set()
        self.loaded_paths.add(str(self.framework_root))
        self.load_strap_modules()

    def load_strap_modules(self):
        for strap_dir in self.framework_root.iterdir():
            if strap_dir.is_dir() and (strap_dir / "__init__.py").exists():
                module_name = strap_dir.name
                if module_name not in self.loaded_modules:
                    self.load_module(module_name, strap_dir)

    def load_module(self, module_name: str, module_path: Path):
        spec = importlib.util.spec_from_file_location(module_name, module_path / "__init__.py")
        if spec is None:
            print(f"[-] Could not load module {module_name} from {module_path}")
            return
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        self.loaded_modules[module_name] = module
        self.loaded_paths.add(str(module_path))
        if spec.loader is not None:
            spec.loader.exec_module(module)


    def load_binary(self, binary_name: str, binary_path: Path):
        if binary_name in self.loaded_binaries:
            return self.loaded_binaries[binary_name]
        try:
            import ctypes
            binary = ctypes.CDLL(str(binary_path))
            self.loaded_binaries[binary_name] = binary
            return binary
        except Exception as e:
            print(f"[-] Could not load binary {binary_name} from {binary_path}: {e}")
            return None


    def ipython_shell(self):
        banner = "Interactive Python shell with loaded modules and binaries."
        local_vars = {**self.loaded_modules, **self.loaded_binaries}
        code.interact(banner=banner, local=local_vars)

    def send_command(self, command: str):
        """
        Sends a command to the C library via the socket.
        """
        import socket
        socket_path = "/tmp/brain.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(socket_path)
            client.sendall(command.encode())
            response = client.recv(1024)
            print(f"Response from C library: {response.decode()}")


async def main():
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        await loop.run_in_executor(executor, loader.ipython_shell)

if __name__ == "__main__":
    asyncio.run(main())
