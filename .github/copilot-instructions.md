# Copilot Instructions

Headless security-research orchestration harness. A local Ollama LLM (the "tool secretary", `daharness/agent.py`) semantically searches a ChromaDB vector-indexed tool registry, picks a module, and executes it with human-in-the-loop approval. Python handles orchestration; C/C++ handles low-level systems work. `AGENTS.md` is the canonical agent doc — consult it for deep architectural detail (Metasploit client quirks, Brain protocol specifics).

## Commands

```bash
pip install -r requirements.txt      # pinned deps
python -m daharness.core            # index tools into the vector registry
python -m daharness.core --clear    # wipe and re-index
python bootstrap.py                 # interactive chat loop; also starts Brain, ZAP, MSF MCP, API gateway
python bootstrap.py --daemon        # services only, no chat
python tool_repl.py                 # operator REPL (bypasses the LLM)
python tool_repl.py run <tool_id> [--flag value ...]   # one-shot tool execution

pytest tests/                       # full suite
pytest tests/test_scope_gate.py     # single file
pytest tests/test_scope_gate.py::test_ffuf_blocked_raises  # single test
```

No lint/format config exists — don't add formatting churn to unrelated changes. Docker lane: `dockered/` (gateway on port **6000**; host lane uses **5000**).

## Architecture

Execution path: secretary LLM → `search_tools` (vector search, returns manifests) → `execute_tool` → transport dispatch → result projection (full|digest|page).

- **Result projection**: `execute_tool` result passes through `utils/result_projection.py` before entering model context. `result_mode` (full|digest|page) is an execution-envelope parameter, not a tool argument. Non-full modes store the full result in `utils/scratch_store.py` and return a compact digest/page + a `scratch_ref` + retrieval instruction. Tools opt in to family-specific digests via `@framework_tool(..., result_digest=fn)`. Default `full` = zero behavior change.
- **Grounding rule**: `execute_tool` rejects any `tool_id` not recorded in `SecretaryDeps.surfaced_tools` — a tool must be surfaced by `search_tools` in the current conversation before it can run. This blocks hallucinated tool calls.
- **Approval loop**: `execute_tool` is `requires_approval=True`; pydantic-ai pauses with `DeferredToolRequests`, the confirmer approves (full manifest + args), then `run_secretary()` resumes with the same `deps` + `result.all_messages()`. Capped by `SECRETARY_MAX_APPROVAL_ROUNDS`.
- **Discovery** (`daharness/registry.py:discover_local_tools`), two passes over `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`, `listeners/`, `utils/`, `encoders/`):
  1. Static `ast` analysis — **never imports**. Module docstring becomes the embedding text; argparse flags become the parameter schema. Runs as subprocess (`LOCAL_FILE`).
  2. Dynamic import — walks members for `@framework_tool` callables (`BRAIN_DISPATCH`). `MCP_RPC` is reserved for external RPC (Metasploit).
- **Brain sidecar** (`listeners/thebrain.py`): UDS server on `/tmp/brain.sock`, 4-byte length-prefixed framing. At startup it scans and **imports** modules in `BRAIN_SCAN_DIRS` (default `auxiliaries,listeners,payloads`) to register `@framework_tool` callables — module-level code runs at Brain boot.
- **In-process fallback** (`daharness/executor.py`): if the Brain socket is down, `@framework_tool` calls execute in-process with cached class instances. If the Brain **accepted** a call but timed out (`BRAIN_DISPATCH_TIMEOUT`, 600s), the result is a failure and the tool is **not** retried in-process — it may still be running on the Brain.
- **Process-local state**: `utils/session_manager.py` (live connections keyed by `session_id`) and class-instance caches exist per-process; in-process fallback cannot see Brain-held sessions. Tools should detect and report this, not silently fail.
- **Scope gate** (`utils/scope_gate.py`): operator-armed via the REPL (`scope on <handle>`), state persisted to `scope/.armed_packet_scope.json` (mtime-checked every call, so REPL changes apply inside a running Brain). Arming is deliberately **not** exposed as an `@framework_tool` so the secretary can never toggle it. Every traffic-sending tool raises `ScopeGateError` on a blocked target.
- **Findings** (`daharness/findings.py` + `utils/findings.py`): SQLite-backed structured findings, with program-scope checks (`check_scope`) and reportability gating.
- **API gateway** (`api_gateway.py`): FastAPI exposing `/tools/execute`, `/tools/search`, `/memory/*`, and a streamable-HTTP MCP endpoint (`/mcp`).

## Conventions

**Adding a tool** — pick one:
1. **argparse module** (`LOCAL_FILE`): `.py` under an allowed root; module docstring = embedding text; `argparse` flags = parameter schema; re-index with `python -m daharness.core`.
2. **`@framework_tool`** (`BRAIN_DISPATCH`): decorate a function or method; the semantic description is the decorator's first argument — write it for good vector matching, not brevity. Google/NumPy-style docstring `Args:` sections and type annotations feed the manifest's parameter schema. Place under a Brain scan dir and re-index or restart the Brain.
3. **C/C++ plugin**: `plugins/*.c` → `gcc -shared -o plugin.so -fPIC plugin.c`; load via `ctypes.CDLL` in a Python wrapper; **always** set `argtypes` and `restype`; use absolute paths built from `Path(__file__).resolve()`; wrap in a `@framework_tool`.

- **Two refresh layers**: REPL `reindex` refreshes manifests only (`run` sees code edits immediately); semantic `search` and the secretary keep seeing **old embeddings** until `python -m daharness.core` runs (then restart the Brain). A doc change is the re-embed signal.
- **No module-level side effects** in scanned dirs — the Brain's startup scan imports them.
- **Tool tags**: every tool carries category tags (canonical vocabulary in `daharness/tool_tags.py:CANONICAL_TAGS`, e.g. `recon.web`, `web.fuzz`, `net.services`). Tag inline via `@framework_tool(doc, tags=[...])` or add to the `TOOL_TAGS` map; tags are appended to the embedded text and change re-embeds on next index.
- **Stateful clients** (SSH, MSF, DB): implement a `get_instance()` classmethod singleton so the Brain and in-process dispatchers share live handles.
- **Blocking calls**: sync tools that block are fine — dispatchers run them in worker threads. Do **not** make a blocking tool async; that freezes the event loop. Conversely, service/listener tools must **not** block: bind the socket, hand serving to a background `asyncio.create_task()`, return immediately (see `listeners/listening.py:listen()`).
- **Long-running CLI tools** (nmap, masscan, ffuf, hydra, sqlmap) follow the background-job pattern in `utils/background_job.py`: `launch_job` returns a `job_id` immediately; tools come in `run_*` / `*_status` / `*_cancel` triples.
- **Configuration**: all knobs come from `.env` (see `.env.example` — timeouts, ports, model selection, scope integrations).

## Safety

The secretary must run on a **locally-hosted model** (`SECRETARY_MODEL` via Ollama, `OLLAMA_BASE_URL` loopback/LAN). Never point the framework at a cloud LLM API — tool outputs from live targets (credentials, tokens, internal IPs) must not egress to third parties.