# AI Agent Instructions: Modular Security Framework

Welcome to the Modular Security Framework. This project is a research-oriented tool designed to study security framework architectures (like Metasploit) through a hybrid Python/C++ implementation.

## 🏗 Architecture Overview

The framework is an MCP-enabled pipeline that follows a "Hybrid Glue" pattern where Python handles orchestration and high-level logic, while C/C++ handles performance-critical and low-level systems interaction.

### 🐍 Pythonic Modules

- **Definition**: Pure Python packages/directories.
- **Location**: Found in top-level directories (e.g., `listeners/`, `utils/`, `payloads/`, `auxiliaries/`).
- **Convention**: Must contain an `__init__.py` to be recognized by the `FrameworkLoader` in `bootstrap.py`.
- **Purpose**: Orchestration, API wrappers, configuration, and rapid feature development.

### ⚙️ Compiled Plugins

- **Definition**: Shared objects (`.so`) compiled from C or C++ source.
- **Location**: Source code is kept in the same folder as the resulting binary (e.g., `listeners/plugins/frameit.c` > `frameit.so`).
- **Convention**:
    - Compiled with `-fPIC` and `-shared`.
    - Loaded via `ctypes.CDLL` in Python.
    - Follows the "C to Raw Byte Array Pipeline" for payloads (see `C_TO_BYTE_ARRAY_PIPELINE.md`).
- **Purpose**: Low-level system calls, raw packet manipulation, and high-performance execution.

## 🛠 Key Components & "Glue" Logic

- **`bootstrap.py`**: The main entry point and daemon. It uses `FrameworkLoader` to launch background servers (Brain, SSL) and initializes the `FrameworkAPI` for remote control.
- **`webserver.py`**: An MCP-compatible FastAPI control panel. It provides authenticated endpoints for dynamic module discovery and remote C/C++ compilation/syntax checking.
- **`listeners/thebrain.py`**: Acts as a bridge. It creates a Unix Domain Socket (`/tmp/brain.sock`) to receive commands from Python and forward them to the loaded C libraries using `ctypes`.
- **`auxiliaries/`**: Contains auxiliary tools like `smb_scanner.py` that perform recon and report findings back to the Brain via the Unix socket.
- **`C_TO_BYTE_ARRAY_PIPELINE.md`**: The definitive guide for converting C code into raw bytes for embedding into the framework.

## 📝 Development Guidelines for Agents

1. **Language Choice**:
    - If the task requires high-level logic, networking wrappers, or configuration > Create a **Python Module**.
    - If the task requires raw memory access, custom assembly, or extreme performance > Create a **C/C++ Plugin**.
2. **Adding Capability**:
    - To add a Python module: Create a folder with an `__init__.py`.
    - To add a C plugin: Create a `.c` file, compile to `.so` in the same folder, and ensure the Python side uses `ctypes` to map the function signatures.
3. **Linking**: Do not duplicate documentation from `C_TO_BYTE_ARRAY_PIPELINE.md` or `README.md`. Refer to them directly.

## ⚠️ Potential Pitfalls

- **Binary Paths**: C plugins are often loaded via relative paths (e.g., `./frameit.so`). Ensure the current working directory is consistent or use absolute paths derived from `FRAMEWORK_ROOT`.
- **C-Types Mapping**: When adding new C functions, always explicitly define `argtypes` and `restype` in Python to avoid segmentation faults.
- **Debugging**: When developing C plugins, use tools like `gdb` or `valgrind` to catch memory errors early. Always test the integration with the Python side to ensure stability.