
import sys
import code
import tempfile
import shlex
import importlib
import importlib.util
from pathlib import Path

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
        """
        Loads all strap modules from the framework root directory.
        """
        for item in self.framework_root.iterdir():
            if item.is_dir() and (item / '__init__.py').exists():
                self.load_module(item.name)
            elif item.is_file() and item.suffix in ['.so', '.exe']:
                self.load_binary(item.name)

    def load_module(self, module_name: str):
        """
        Loads a Python module by name.
        """
        if module_name in self.loaded_modules:
            return self.loaded_modules[module_name]

        module_path = self.framework_root / module_name
        spec = importlib.util.spec_from_file_location(module_name, module_path / '__init__.py')
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot find module {module_name}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        self.loaded_modules[module_name] = module
        return module

    def load_binary(self, binary_name: str):
        """
        Loads a binary file by name.
        """
        if binary_name in self.loaded_binaries:
            return self.loaded_binaries[binary_name]

        binary_path = self.framework_root / binary_name
        if not binary_path.exists():
            raise FileNotFoundError(f"Cannot find binary {binary_name}")

        self.loaded_binaries[binary_name] = binary_path
        return binary_path

    def get_loaded_modules(self):
        """
        Returns a dictionary of loaded modules.
        """
        return self.loaded_modules

    def get_loaded_binaries(self):
        """
        Returns a dictionary of loaded binaries.
        """
        return self.loaded_binaries
    
    def interactive_shell(self):
        """
        Starts an interactive Python shell with the loaded modules and binaries in the context.
        """
        local_vars = {**self.loaded_modules, **self.loaded_binaries}
        code.interact(local=local_vars)

if __name__ == "__main__":
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    print("Loaded modules:", loader.loaded_modules.keys())
    print("Loaded binaries:", loader.loaded_binaries.keys())
    interactive_shell = input("Do you want to start an interactive shell? (y/n): ")
    if interactive_shell.lower() == 'y':
        loader.interactive_shell()
    else:
        print("Exiting.")
