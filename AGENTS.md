# AI Agent Instructions: Modular Security Framework

A headless orchestration harness for security research. A local LLM ("tool
secretary") semantically searches a vector-indexed tool registry, selects a
module, and executes it with human-in-the-loop approval. Python handles
orchestration; C/C++ handles low-level systems work.

See `README.md` for the user-facing overview. This document is for agents
working **on** the codebase.

## Architecture

### Tool Secretary (`daharness/`)

The core agent loop lives in `daharness/core.py`. A local Ollama model
(default `gemma4:12b`) is given two tools via a `FunctionToolset`:

- **`search_tools`** — semantic search over the ChromaDB tool registry.
  Returns full manifests. Every result is recorded in
  `SecretaryDeps.surfaced_tools`.
- **`execute_tool`** — runs a surfaced tool. Declared
  `requires_approval=True`, so pydantic-ai pauses the run with
  `DeferredToolRequests`. The confirmer sees the full manifest + arguments
  and must approve before execution proceeds.

**Grounding rule:** `execute_tool` rejects any `tool_id` not in
`SecretaryDeps.surfaced_tools`. Even if the tool exists in the registry, the
agent must call `search_tools` first. This prevents hallucinated tool calls.

**Approval loop:** `run_secretary()` handles the `DeferredToolRequests` ->
confirmer -> resume cycle. Up to `SECRETARY_MAX_APPROVAL_ROUNDS` (default 10)
rounds per turn. Pass the same `deps` + `result.all_messages()` back in to
continue a conversation.

**Post-execution:** after an approved execution, `_tail_framework_logs()`
appends the last 50 lines of Brain/MSF logs to the result for visibility.

The `daharness/` package splits imports across focused modules:
- `daharness.core` — everything (registry, secretary, chat loop, embedding)
- `daharness.agent` — `create_secretary_agent()` factory
- `daharness.executor` — standalone execution helpers (no ChromaDB client)
- `daharness.registry` — `ToolRegistry`, `OllamaEmbeddingFunction`
- `daharness.models` — `ToolManifest`

### Tool Discovery (`daharness/core.py:discover_local_tools`)

Two passes scan `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`,
`listeners/`, `utils/`, `encoders/`):

1. **Static AST analysis** (`LOCAL_FILE` transport): `extract_module_profile()`
   parses each `.py` with `ast` — **never imports** — extracting the module
   docstring and `argparse` options. Docstrings become the embedding text;
   argparse flags become the JSON-schema-ish `parameters`. These tools run as
   subprocesses via `_execute_local_script()`.

2. **Dynamic import** (`BRAIN_DISPATCH` transport): imports the module and
   walks its members for `@framework_tool`-decorated functions and methods.
   Methods on classes defined in that module are minted with the class name
   in the tool_id (e.g. `payloads.metasploiting.MetasploitClient.index_modules`).
   These dispatch via the Brain socket or fall back in-process.

`__init__.py` files are **skipped**, not required. Skip dirs: `venv`,
`.venv`, `__pycache__`, `.git`, etc. Skip files: `bootstrap.py`,
`memories.py`, `owui-tool.py`.

### `@framework_tool` Decorator (`constants.py`)

```python
from constants import framework_tool, TransportType

@framework_tool("Semantic description of what this tool does.")
def my_tool(target, port):
    ...

# For methods on stateful classes:
class MyClient:
    @framework_tool("Does something using this client's live connection.")
    def do_thing(self, target):
        ...
```

Sets `_is_framework_tool = True`, `_tool_doc` (the semantic description used
for embedding), and `_transport` (default `BRAIN_DISPATCH`).

### Transport Types (`constants.py:TransportType`)

| Transport | How it executes | Used by |
|---|---|---|
| `LOCAL_FILE` | Subprocess: `python <script> --key value` | argparse modules discovered statically |
| `BRAIN_DISPATCH` | Brain UDS socket -> function registry, or in-process fallback | `@framework_tool` functions/methods |
| `MCP_RPC` | External RPC (Metasploit). Partially implemented. | `metasploiting.py` execute_module |

### Brain Sidecar (`listeners/thebrain.py`)

Unix domain socket server at `/tmp/brain.sock` with 4-byte big-endian
length-prefixed message framing (`pack_message` / `read_message`).

**Startup sequence:**
1. Probe for an existing live listener (refuses to start a second Brain).
2. Unlink stale socket if no live listener.
3. `_startup_scan()` — imports modules under `BRAIN_SCAN_DIRS` (default:
   `auxiliaries,listeners,payloads`) and registers `@framework_tool`
   callables in `FunctionRegistry`.
4. Bind the socket (only after scan completes, so tools are callable
   immediately when bootstrap's connect-probe succeeds).

**Event protocol:** `event_type|session_id|data`
- `SCAN_TOOLS|sid|path` — scan a directory/file for tools, register them.
- `CALL_TOOL|sid|tool_id|args_json` — execute a registered tool. Args as
  dict -> kwargs, list -> positional, or bare string -> single positional.
- Unknown events -> forwarded to C library (`frameit.so`) via `ctypes`.

**Class instance caching:** `FunctionRegistry._instances` keeps one instance
per class so stateful clients (e.g. `MetasploitClient`) preserve handles
across calls.

**Shutdown:** signal handlers route SIGTERM/SIGINT through task cancellation
so the `finally` block unlinks the socket — but only if the inode still
matches the one we bound (won't clobber a newer sidecar).

### In-Process Fallback (`daharness/core.py:_execute_brain_tool`)

When the Brain socket is unavailable (`FileNotFoundError`, `ConnectionError`)
or doesn't know the tool, execution falls back to `_launch_in_process()`:

1. `_resolve_callable()` — longest importable module prefix wins, walks
   remaining attrs. Unbound methods are bound to a cached class instance
   (`_tool_instances`), preferring `get_instance()` if available.
2. Async tools are awaited; sync tools run in `asyncio.to_thread()`.
3. Results are wrapped as `{"stdout", "status"}` dicts.

**Important:** if the Brain accepted the call but timed out
(`BRAIN_DISPATCH_TIMEOUT`, default 180s), the result is a failure and the
tool is **not** retried in-process — it may still be running on the Brain,
and a second execution would cause duplicate side effects.

### Bootstrap (`bootstrap.py`)

Entry point and daemon. `FrameworkLoader.launch_all()` starts:
- Brain sidecar (subprocess, logs to `/tmp/brain.log`)
- SSL server (subprocess, compiled binary)
- API gateway (async task, `api_gateway.py`, port 6000)
- Metasploit MCP (launches `msfconsole` with `msgrpc`, waits for RPC port)

Interactive mode: indexes tools via `bootstrap_registry()`, then enters
`_chat()` REPL. Daemon mode (`--daemon`): starts services and waits for
SIGTERM/SIGINT.

### API Gateway (`api_gateway.py`)

FastAPI server (port 6000):
- `POST /tools/execute` — semantic lookup (`find_best_tool`) + execution
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall

### Memory Service (`memories.py`)

ChromaDB persistent client (`.memory/chroma`). Namespaced collections
(`memory_<namespace>`). Operations: `remember`, `search` (keyword),
`recall` (vector), `get`, `forget`. Session-scoped filtering via
`where` clauses. All five operations are `@framework_tool`-decorated.

### Session Manager (`utils/session_manager.py`)

Thread-safe singleton holding live connection objects keyed by `session_id`
(e.g. `sess-0001`). Tools call `register()` on open, `get()` for follow-up
commands. `cleanup_stale()` closes sessions idle beyond a threshold.

**Process-local:** sessions live in whichever process ran the tool (Brain or
in-process launcher). If the Brain dies and a call falls back in-process,
it cannot see sessions the Brain was holding.

### Metasploit Client (`payloads/metasploiting.py`)

`MetasploitClient` uses `pymetasploit3` RPC. Singleton via `get_instance()`
so bootstrap's `start_mcp()` and in-process tool launches share the same
`msfconsole` handle. Tools: `index_modules`, `execute_module` (polls for new
sessions), `set_payload`, `get_options`, `list_sessions`,
`interact_session`, `close_msf_session`.

### OpenWebUI Tool (`owui-tool.py`)

External tool definitions that call the framework API for tool execution and
memory operations. Used to expose the framework as a tool in OpenWebUI.

## Development Guidelines

### Adding a Tool

**Option A — argparse module (LOCAL_FILE):**
1. Create a `.py` file under an allowed root (`auxiliaries/`, `payloads/`,
   `listeners/`, `utils/`, `encoders/`).
2. Add a module-level docstring (this becomes the embedding text).
3. Use `argparse` with `add_argument` calls — the static scanner extracts
   flags, types, and required-ness into the parameter schema.
4. Re-index: `python -m daharness.core` (or `--clear` to wipe first).

**Option B — `@framework_tool` function/method (BRAIN_DISPATCH):**
1. Import `framework_tool` from `constants`.
2. Decorate the function or method. The doc string is the semantic
   description — make it descriptive for good vector matching.
3. Place the module under a Brain scan dir (default: `auxiliaries/`,
   `listeners/`, `payloads/`).
4. Re-index or restart the Brain sidecar.

**Option C — C/C++ plugin:**
1. Write `.c`/`.cpp` in a `plugins/` subdirectory.
2. Compile: `gcc -shared -o plugin.so -fPIC plugin.c`
3. Load via `ctypes.CDLL` in a Python wrapper.
4. **Always** set `argtypes` and `restype` explicitly.
5. Wrap the ctypes call in a `@framework_tool` function for discovery.

### Language Choice

- High-level logic, networking wrappers, configuration → **Python module**.
- Raw memory access, custom assembly, extreme performance → **C/C++ plugin**.
- Anything that should be semantically discoverable and LLM-callable → wrap
  it in a `@framework_tool` function.

### Stateful Clients

If a tool class holds live connections (SSH, MSF, database):
- Implement a `get_instance()` classmethod returning a shared singleton.
- The registry's `_tool_instances` cache and the Brain's
  `FunctionRegistry._instances` both prefer `get_instance()` when binding
  methods, so all callers share the same live handles.
- Register long-lived connections with `SessionManager` for cross-tool
  retrieval by `session_id`.

### Blocking Calls

Sync tools that block (subprocess, impacket, nmap) are fine — both
dispatchers run sync tools in a worker thread (`run_in_executor` /
`asyncio.to_thread`). Do **not** make them async just to "be async" — that
pins the blocking call to the event loop and freezes the harness.

### Listener/Service Tools

Tools that start a long-running service (TCP listener, etc.) must **not**
block — `serve_forever()` would hang the dispatcher. Bind the socket, hand
serving off to a background `asyncio.create_task()`, and return immediately.
See `listeners/listening.py:listen()` for the pattern.

## Pitfalls

- **Stale Brain socket:** the kernel doesn't unlink a socket when its owner
  dies. Always probe with a real `connect()`, not `Path.exists()`. The Brain
  unlinks on clean shutdown but not on SIGKILL. Bootstrap's `_brain_ready()`
  handles this.
- **Brain timeout = no in-process retry:** if the Brain accepted a call but
  didn't reply within `BRAIN_DISPATCH_TIMEOUT`, the result is a failure and
  the tool is **not** retried in-process (it may still be running). Check
  sidecar logs before retrying.
- **Circular imports:** `listeners/thebrain.py` is launched directly, which
  puts `listeners/` on `sys.path` instead of the framework root. It inserts
  `_FRAMEWORK_ROOT` at the top of `sys.path` on import. If you add imports
  from thebrain, be aware of this.
- **Brain startup scan vs. discovery scan:** the Brain's `_startup_scan()`
  imports modules to register `@framework_tool` callables — this **runs
  module-level code**. The registry's static pass does not. Keep
  module-level side effects out of scanned modules, or exclude them from
  `BRAIN_SCAN_DIRS`.
- **sys.path collisions:** scanning a bare directory (not a package) derives
  module names like `nmap`, which can collide with installed packages
  (e.g. `python-nmap`). The Brain's `scan_tools()` handles this by checking
  for `__init__.py` and adjusting the import path.
- **ctypes signatures:** always define `argtypes` and `restype` explicitly.
  Missing signatures cause silent type coercion or segfaults.
- **C plugin paths:** use `Path(__file__).resolve().parent / "plugins" /
  "name.so"` for absolute paths. Relative paths break when the CWD changes.
- **Process-local sessions:** `SessionManager` is per-process. If the Brain
  dies and a call falls back in-process, sessions created on the Brain are
  invisible. Design tools to detect and report this, not silently fail.
- **`_raw` argument passthrough:** the secretary wraps unparseable JSON args
  as `{"_raw": ...}`. `_launch_in_process()` strips `_raw` before calling
  the tool. Don't rely on it being present in your tool function.
- **Debugging C plugins:** use `gdb` or `valgrind`. Test the Python
  integration separately to catch `ctypes` mapping errors.
