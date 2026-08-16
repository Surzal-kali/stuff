# Copilot Instructions

## Commands

- Python dependencies are pinned in `requirements.md`; install them with `venv/bin/python -m pip install -r requirements.md`.
- Run the framework loader from the repository root with `venv/bin/python framework/bootstrap.py`. It opens an interactive Python shell after scanning modules.
- Build the OpenSSL listener with `make -C framework/utils/sslserver`; it produces `framework/utils/sslserver/ssl_server.exe` and requires OpenSSL development headers and libraries.
- There is no repository-defined test runner, single-test command, lint command, or type-check command. Do not invent test selectors or assume the pinned `ruff`, `black`, and `pyright` packages are configured.

## Architecture

- `framework/bootstrap.py` is the plugin loader. It scans only immediate, non-hidden child directories of `framework/`, treating immediate `.py` files as importable modules and all other immediate files as static payloads/resources. It does not recurse into nested directories.
- The Python modules are organized by capability: `auxiliaries/networkscan.py` performs Scapy-based discovery; `listeners/listening.py` provides the asyncio TCP listener; and `utils/packetcraft.py` centralizes Scapy packet construction and capture helpers.
- `utils/sessions.py` owns the SQLite persistence boundary. `Database_Manager` opens `ids.db` relative to the process working directory, initializes `targets`, `sessions`, and `notes`, and supports context-manager cleanup. Keep the implementation and `schema.md` aligned when changing stored entities.
- Native components are standalone rather than integrated with the Python loader: `utils/sslserver/` is a C/OpenSSL echo server, while `payloads/listen.cpp` and `encoders/embed.cpp` are source templates requiring compile-time macros (`TARGET` and `SHELL_PAYLOAD`, respectively).

## Repository-Specific Conventions

- Loading is import-driven: module-level code in any immediate Python file under a framework category runs during `FrameworkLoader.scan()`. Keep newly loadable modules free of prompts, network actions, and other side effects at import time. In particular, `networkscan.py` currently prompts for `TARGET_RANGE` at import time, so running the bootstrap loader is interactive.
- Preserve the loader's category/file contract when adding modules: place a Python module directly in its category directory; do not rely on package `__init__.py` files or nested source directories being discovered.
- Packet construction uses Scapy layer composition (`/`) and shared `PacketCraft`/`PacketUtils` helpers. `TARGET_INTERFACE` defaults to `eth0`; pass an interface to `PacketCraft` instead of duplicating capture/send logic.
- Network scanning and packet sending may require elevated privileges. The checked-in VS Code Python launch configurations intentionally use the project `venv` and `sudo` for those workflows.
- The asyncio listener accepts its port as a positional argument and `--host` as an optional bind address; retain that interface for compatible listener changes.
- The native SSL server loads `cert.pem` and `key.pem` from its current working directory and listens on port `4433`; run it from `framework/utils/sslserver` when using its default paths.
