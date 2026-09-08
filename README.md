# Modular Security Framework

A headless, MCP-capable orchestration harness for security research. A small
local LLM (the "tool secretary") semantically searches a vector-indexed tool
registry, selects the right module for a natural-language request, and
executes it — with a human-in-the-loop approval gate on every execution.

The framework follows a "hybrid glue" architecture: Python handles
orchestration, agent loops, and API surfaces; C/C++ handles performance-critical
and low-level systems work (raw sockets, packet framing).

## Architecture

### Tool Secretary (`daharness/`)

The core of the framework. A local LLM (Ollama, e.g. `qwen3:14b`) acts as a
conversational agent with two tools:

1. **`search_tools`** — semantic search over the tool registry (ChromaDB,
   `nomic-embed-text` embeddings, HNSW cosine similarity). Returns full tool
   manifests.
2. **`execute_tool`** — runs a surfaced tool. **Requires human approval**:
   the run pauses, the operator sees the full manifest + arguments, and
   approves or denies before anything executes.

**Grounding rule:** the secretary can only execute tools it has seen returned
by `search_tools` in the current conversation. A tool_id that was never
surfaced is rejected — the model cannot hallucinate a tool into existence.

The `daharness/` package exposes focused import paths:
- `daharness.core` — backwards-compat shim re-exporting legacy public names
- `daharness.agent` — secretary agent factory
- `daharness.executor` — standalone execution helpers (no ChromaDB needed)
- `daharness.registry` — discovery and semantic search API
- `daharness.models` — `ToolManifest` pydantic model

### Tool Discovery

Two passes scan the workspace at bootstrap:

1. **Static AST analysis** (`LOCAL_FILE` transport): parses Python modules
   with `ast` — never imports them — extracting docstrings and `argparse`
   options to mint `ToolManifest`s. These run as subprocesses.
2. **Dynamic import** (`BRAIN_DISPATCH` transport): imports modules and
   discovers functions/methods decorated with `@framework_tool`. These
   dispatch through the Brain sidecar or fall back to in-process execution.

A third transport, `MCP_RPC`, is reserved for external RPC integrations
(Metasploit).

### Brain Sidecar (`listeners/thebrain.py`)

A Unix domain socket server (`/tmp/brain.sock`) with length-prefixed message
framing. At startup it scans `auxiliaries/`, `listeners/`, and `payloads/`
for `@framework_tool` callables and primes its function registry before
binding the socket. It dispatches `CALL_TOOL` events to registered Python
functions, and forwards unknown events to a C library (`frameit.so`) via
`ctypes`.

When the Brain is unavailable, `BRAIN_DISPATCH` tools fall back to in-process
execution with cached class instances (so stateful clients like
`MetasploitClient` keep their handles).

### `@framework_tool` Decorator (`constants.py`)

```python
from constants import framework_tool, TransportType

@framework_tool("Run an Nmap scan on a target with specified options.")
def run_nmap(target, options="-Pn -sV"):
    ...
```

Marks a function or method as a callable framework tool. The doc string
becomes the semantic capability description that the registry embeds.

## Tool Modules

| Module | Transport | Description |
|---|---|---|
| `auxiliaries/nmap.py` | BRAIN_DISPATCH | Nmap port/service scanning |
| `auxiliaries/smb_scanner.py` | BRAIN_DISPATCH | SMB null session vulnerability scanning |
| `payloads/metasploiting.py` | BRAIN_DISPATCH / MCP_RPC | Metasploit module search, execution, session polling, interaction |
| `utils/paramiko_client.py` | BRAIN_DISPATCH | Persistent SSH (connect/exec/shell/close) + one-shot mode |
| `utils/packetcraft.py` | BRAIN_DISPATCH | Scapy packet crafting: craft_*(icmp/tcp/udp/arp/vlan/dhcp/dns/mdns/http), send_packet, sniff_packets, dissect_packet, modify_packet, save/load pcap |
| `utils/log_reader.py` | BRAIN_DISPATCH | Read/stream Brain and MSF logs |
| `listeners/listening.py` | BRAIN_DISPATCH | TCP listener with Brain event forwarding |
| `listeners/raw_scan.py` | BRAIN_DISPATCH | Raw SYN port scanner (C++ plugin via ctypes) |
| `memories.py` | BRAIN_DISPATCH | Namespaced vector memory (remember/search/recall/get/forget) |

### C/C++ Plugins

- `listeners/plugins/raw_scan.cpp` → `raw_scan.so` — raw SYN scan using
  `SOCK_RAW` (requires root or `CAP_NET_RAW`)
- `listeners/plugins/frameit.c` → `frameit.so` — C-side event bridge for the
  Brain
- `utils/plugins/sslserver/` — standalone SSL server binary
- `payloads/plugins/listen.cpp` — payload listener stub

Compiled with `-fPIC -shared`; loaded via `ctypes.CDLL`.

## External Dependencies

### OWASP ZAP
The framework integrates with ZAP for automated web scanning.
1. Install ZAP on your system (e.g., `sudo apt install zap` or download from the official site).
2. Ensure the `zap` binary is in your PATH or located at `/usr/share/zap/zap.sh`.
3. The framework launches ZAP in `-daemon` mode and manages its configuration automatically.


## Supporting Services

### Memory Service (`memories.py`)

ChromaDB-backed persistent, namespaced vector memory for cross-harness
recall. Supports keyword search and vector similarity recall, with
session-scoped filtering. Exposed both as `@framework_tool` methods and via
the API gateway.

### Session Manager (`utils/session_manager.py`)

Process-local singleton holding live connection objects (SSH clients, MSF
sessions) keyed by `session_id`. Tools register connections on open and
retrieve them for follow-up commands without re-authenticating. Includes
stale-session cleanup.

### SQLite Database (`utils/sessions.py`)

Tracks targets, sessions, payloads, and notes in `ids.db`. Schema defined
in `schema.md`.

### API Gateway (`api_gateway.py`)

FastAPI server (port 6000) exposing:
- `POST /tools/execute` — semantic tool lookup + execution
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall

### OpenWebUI Integration (`owui-tool.py`)

External tool definitions for OpenWebUI that call the framework API for
tool execution and memory operations.

## Quick Start

### Prerequisites

- Python 3.13+
- [Ollama](https://ollama.ai) running with `nomic-embed-text` and a chat
  model (default: `qwen3:14b`)
- ChromaDB server (default: `localhost:9000`)
- Metasploit Framework (optional, for MSF integration)
- Root or `CAP_NET_RAW` (optional, for raw SYN scanning)

### Configuration

Environment variables (see `.env`):

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | `your-ip-address:11434/v1` | Ollama API endpoint |
| `CHROMA_HOST` | `localhost` | ChromaDB host |
| `CHROMA_PORT` | `9000` | ChromaDB port |
| `SECRETARY_MODEL` | `qwen3:14b` | LLM model for the tool secretary |
| `MSGRPC_PASSWORD` | — | Metasploit RPC password |
| `MSF_RPC_PORT` | `55552` | Metasploit RPC port |
| `BRAIN_DISPATCH_TIMEOUT` | `180` | Brain socket dispatch timeout (seconds) |
| `BRAIN_SCAN_DIRS` | `auxiliaries,listeners,payloads` | Directories the Brain scans at startup |
| `WORKSPACE_ROOT` | current directory | Root for tool path resolution |

### Running

```bash
# Install dependencies
pip install -r requirements.txt

# Index tools into the vector registry
python -m daharness.core

# Clear and re-index
python -m daharness.core --clear

# Interactive chat with the secretary (daemon mode starts all sidecars)
python bootstrap.py            # interactive (indexes + chat)
python bootstrap.py --daemon   # background services only

# Run tests
pytest tests/
```

## Adding a New Tool

### Python module (argparse, runs as subprocess)

1. Create a `.py` file under `auxiliaries/`, `payloads/`, `listeners/`,
   `utils/`, or `encoders/`.
2. Add a module docstring describing the capability.
3. Use `argparse` for CLI options — the static scanner extracts them as the
   parameter schema.
4. Re-run `python -m daharness.core` to index it.

### Decorated function/method (dispatched via Brain or in-process)

1. Import `framework_tool` from `constants`.
2. Decorate your function or class method:
   ```python
   from constants import framework_tool

   @framework_tool("Description of what this tool does.")
   def my_tool(target, port):
       ...
   ```
3. Place the module under `auxiliaries/`, `listeners/`, or `payloads/`
   (the Brain's default scan dirs).
4. Re-index or restart the Brain sidecar.

### C/C++ plugin

1. Write a `.c` or `.cpp` file in a `plugins/` subdirectory.
2. Compile: `gcc -shared -o plugin.so -fPIC plugin.c`
3. Load via `ctypes.CDLL` in a Python wrapper, explicitly defining
   `argtypes` and `restype`.

## Safety Notes

- **Human-in-the-loop:** every tool execution requires explicit approval.
  The confirmer sees the full manifest and arguments before approving.
- **Path confinement:** local script execution is restricted to
  `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`, `listeners/`, `utils/`,
  `encoders/`).
- **No import at discovery time:** static analysis uses `ast` only — hostile
  or broken code cannot execute during indexing.
- **Timeouts:** Brain dispatch and subprocess execution are bounded to
  prevent hanging the conversation loop.

## Project Layout

```
daharness/          Tool secretary agent + semantic registry (core package)
constants.py        @framework_tool decorator + TransportType enum
bootstrap.py        Daemon entry point; launches all sidecars
api_gateway.py      FastAPI control panel (port 6000)
memories.py         ChromaDB-backed namespaced vector memory
listeners/
  thebrain.py       Unix socket sidecar + function registry
  listening.py      TCP listener with Brain integration
  raw_scan.py       SYN scanner wrapper (C++ plugin)
  plugins/          C/C++ shared objects (frameit, raw_scan)
payloads/
  metasploiting.py  Metasploit RPC client (search/execute/sessions)
  plugins/          Payload listener (C++)
auxiliaries/
  nmap.py           Nmap scanner
  smb_scanner.py    SMB null session scanner
utils/
  paramiko_client.py   Persistent SSH tools
  session_manager.py   Singleton for live session objects
  sessions.py          SQLite database (targets/sessions/notes)
  log_reader.py        Brain/MSF log reading and streaming
  packetcraft.py       Scapy packet crafting (craft_*/send_packet/sniff_packets/dissect_packet/modify_packet)
  plugins/sslserver/   SSL server binary
encoders/           Encoder plugins (C/C++)
tests/              pytest suite for registry + secretary flows
schema.md           SQLite database schema
AGENTS.md           AI agent development guide
```
