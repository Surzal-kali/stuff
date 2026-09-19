# Modular Security Framework

A headless, MCP-capable orchestration harness for security research and
bug-bounty automation. A small local LLM (the "tool secretary") semantically
searches a vector-indexed tool registry, selects the right module for a
natural-language request, and executes it — with a human-in-the-loop approval
gate on every execution.

The framework follows a "hybrid glue" architecture: Python handles
orchestration, agent loops, and API surfaces; C/C++ handles performance-critical
and low-level systems work (raw sockets, packet framing).

The framework is built around a **hunt lifecycle**: load a HackerOne program
scope, enumerate the attack surface, run scanners against in-scope targets,
gather evidence, and file structured findings — all coordinated by the
secretary model and gated by scope-compliance and reportability checks.

## Architecture

### Tool Secretary (`daharness/`)

The core of the framework. A local LLM (Ollama; `SECRETARY_MODEL`, default
`hf.co/unsloth/GLM-4.7-Flash-GGUF:Q3_K_M`) acts as a
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
- `daharness.findings` — SQLite-backed findings store (`FindingStore`)
- `daharness.models` — `ToolManifest` and `Finding` pydantic models

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

- **`auxiliaries/program_scope.py`** — **BRAIN_DISPATCH**: HackerOne scope integration: load program scope, check_scope, check_reportable, program_hacktivity
- **`auxiliaries/impacket_suite.py`** — **BRAIN_DISPATCH**: Impacket post-exploitation: SMB enum/read, secretsdump, psexec/wmiexec/atexec
- **`auxiliaries/ssh_exec.py`** — **BRAIN_DISPATCH**: SSH batch command execution on a persistent connection
- **`auxiliaries/smb_scanner.py`** — **BRAIN_DISPATCH**: SMB null session vulnerability scanning
- **`auxiliaries/cert_tools.py`** — **BRAIN_DISPATCH**: TLS certificate generation/clearing for the OOB collaborator
- **`auxiliaries/framework_status.py`** — **BRAIN_DISPATCH**: Framework operational health check (Brain, Ollama, ChromaDB, ZAP)
- **`payloads/metasploiting.py`** — **BRAIN_DISPATCH / MCP_RPC**: Metasploit module search, execution, session polling, interaction
- **`payloads/ffuf.py`** — **BRAIN_DISPATCH**: ffuf web fuzzing: directories, files, vhosts, parameters (launch/poll/cancel)
- **`payloads/hydra.py`** — **BRAIN_DISPATCH**: Hydra credential brute-force / password-spray (launch/poll/cancel)
- **`payloads/sqlmap.py`** — **BRAIN_DISPATCH**: sqlmap SQL injection detection (launch/poll with injectable verdict parsing)
- **`payloads/searchsploiting.py`** — **BRAIN_DISPATCH**: searchsploit (ExploitDB) lookup for known exploits
- **`payloads/fastcgi.py`** — **BRAIN_DISPATCH**: FastCGI/PHP-FPM exploitation (raw request + php://input RCE chain)
- **`payloads/wordlists.py`** — **BRAIN_DISPATCH**: Discover and list available wordlist files
- **`utils/findings.py`** — **BRAIN_DISPATCH**: Report, render, close, and supersede structured security findings
- **`utils/paramiko_client.py`** — **BRAIN_DISPATCH**: Persistent SSH (connect/exec/shell/close) + one-shot mode
- **`utils/packetcraft.py`** — **BRAIN_DISPATCH**: Scapy packet crafting: craft_*(icmp/tcp/udp/arp/vlan/dhcp/dns/mdns/http), send_packet, sniff_packets, dissect_packet, modify_packet, save/load pcap
- **`utils/log_reader.py`** — **BRAIN_DISPATCH**: Read/stream Brain and MSF logs
- **`utils/memory_tools.py`** — **BRAIN_DISPATCH**: Namespaced vector memory (remember_text/recall_text)
- **`utils/background_job.py`** — **Helper**: Shared background-job launch/poll helper for long-running CLI tools
- **`utils/handles.py`** — **Helper**: Session handle formatting, parsing, and validation
- **`listeners/listening.py`** — **BRAIN_DISPATCH**: TCP listener with Brain event forwarding
- **`listeners/collaborator.py`** — **BRAIN_DISPATCH**: OOB callback listener (Burp Collaborator analog): HTTP/HTTPS/DNS on one host
- **`listeners/raw_scan.py`** — **BRAIN_DISPATCH**: Raw SYN port scanner (C++ plugin via ctypes)
- **`memories.py`** — **BRAIN_DISPATCH**: Namespaced vector memory (remember/search/recall/get/forget)

### Background Job Pattern

Long-running CLI tools (nmap, masscan, amass, ffuf, hydra, sqlmap) use the
shared `utils/background_job.py` helper: `launch_job` starts a detached
`subprocess.Popen`, writes a JSON sidecar to disk (so polls survive a
harness restart), starts a reaper thread for the wall-clock cap, and
returns a `job_id` immediately — the secretary turn is not held open.
`poll_job` reads the log, checks liveness, tails recent lines, and returns
a structured `status: "running" | "done"` dict. Each tool pair follows the
`run_*` / `*_status` / `*_cancel` shape.

### C/C++ Plugins

- `listeners/plugins/raw_scan.cpp` → `raw_scan.so` — raw SYN scan using
  `SOCK_RAW` (requires root or `CAP_NET_RAW`)
- `listeners/plugins/frameit.c` → `frameit.so` — C-side event bridge for the
  Brain

- `payloads/plugins/listen.cpp` — payload listener stub

Compiled with `-fPIC -shared`; loaded via `ctypes.CDLL`.

## External Dependencies

The framework wraps several external security tools. Each is invoked as a
subprocess by the corresponding module; install the CLI binary and ensure it
is in your `PATH`.

| Tool | Module | Notes |
|---|---|---|
| **Nmap** | `auxiliaries/nmap.py` | Port/service scanning |
| **Masscan** | `auxiliaries/masscan.py` | Fast async port scanning; requires root or `CAP_NET_RAW` |
| **OWASP Amass** | `auxiliaries/amass.py` | Subdomain enumeration (v5+; passive mode by default) |
| **OWASP ZAP** | `auxiliaries/zap.py` | Web app scanning; launched in `-daemon` mode by `bootstrap.py` |
| **Radare2** | `auxiliaries/radare2.py` | Static binary analysis; `r2pm -ci r2ghidra` for decompilation |
| **Metasploit Framework** | `payloads/metasploiting.py` | MSF RPC integration (MCP sidecar started by `bootstrap.py`) |
| **ffuf** | `payloads/ffuf.py` | Web content fuzzing |
| **Hydra** | `payloads/hydra.py` | Credential brute-force |
| **sqlmap** | `payloads/sqlmap.py` | SQL injection detection |
| **searchsploit** | `payloads/searchsploiting.py` | ExploitDB local lookup |
| **Impacket** | `auxiliaries/impacket_suite.py` | Windows post-exploitation (SMB, psexec, wmiexec, atexec, secretsdump) |
| **Scapy** | `utils/packetcraft.py` | Packet crafting/sniffing (Python library) |
| **Paramiko** | `utils/paramiko_client.py`, `auxiliaries/ssh_exec.py` | SSH client (Python library) |

### OWASP ZAP

1. Install ZAP (`sudo apt install zaproxy` on Debian/Ubuntu/Kali — the plain
   `zap` package name does not resolve — or download from the official
   site).
2. Ensure the `zap` binary is in your PATH or at `/usr/share/zap/zap.sh`.
3. The framework launches ZAP in `-daemon` mode (loopback-only API) and
   manages its configuration automatically. The home directory is pinned to
   `.zap_home/` in the workspace root. ZAP is never run as root — the
   launcher drops to the original user if the framework was started with
   `sudo`. The ZAP *browser-proxy* listener binds `ZAP_PROXY_BIND`
   (default `0.0.0.0`) for upstream proxying; only the daemon's API is
   restricted to loopback.
4. Set `ZAP_API_KEY` in `.env`; it is sent as the `apikey` query parameter on
   every API call.

### Metasploit Framework

1. Install Metasploit Framework.
2. Set `MSGRPC_PASSWORD` and `MSF_RPC_PORT` in `.env`.
3. `bootstrap.py` starts the MSF MCP sidecar (`msfrpcd`) automatically and
   vectorizes discovered modules into the tool registry.


### Docker deployment (`dockered/`)

A containerized workbench lives in `dockered/` and bind-mounts the live
source tree (code edits on the host need no rebuild). Start with
`cd dockered && ./up.sh` (removes a legacy standalone `chroma` container
first). Services:

| Service | Host port | Notes |
|---|---|---|
| ChromaDB (`chroma`) | `9000` | Reuses the existing `chroma-data/` volume |
| Open Terminal | `8000` | Agent shell + file browser; hosts the framework gateway |
| Framework gateway (in Open Terminal) | `6000` | REST + MCP — container lane; bare-metal host lane is `5000` |
| Open WebUI | `3000` | Chat front end; calls the framework API routes |
| JupyterLab | `8888` | Tool nursery; localhost-only, `JUPYTER_TOKEN`-gated |

Keys come from `dockered/.env`: `GATEWAY_API_KEY`, `OPEN_TERMINAL_API_KEY`,
`JUPYTER_TOKEN`.

## Supporting Services

### Findings Store (`daharness/findings.py`)

SQLite-backed findings store — the single source of truth for reported
findings, living in the `findings` table of `ids.db`. The `Finding` pydantic
model (`daharness.models.Finding`) carries title, severity (P1–P4), CWE,
asset, evidence (request/response/excerpt), reproduction steps, tool chain,
and a full lifecycle: `open` → `closed` / `false_positive` / `duplicate` /
`superseded`, with `closed_by`, `closed_reason`, and `superseded_by` for
audit trails.

The full finding objects **never** enter the secretary model's context. Only
a one-line pointer is stored in vector memory (ChromaDB, `findings`
namespace) so the secretary can recall that a finding *exists* without
bloating its context with the full evidence payload.

Framework tools in `utils/findings.py`:
- **`report_finding`** — the terminal action for any tool chain. Mints a
  structured finding and stores a one-line memory pointer.
- **`render_findings`** — renders all findings as a markdown report (filters
  by severity/asset/status). Also writes a timestamped `.md` file to
  `findings_md/` so reports persist outside the database.
- **`close_finding`** — close a finding as resolved, false positive, or
  duplicate.
- **`supersede_finding`** — mark an older finding as replaced by a newer,
  more accurate one.

### HackerOne Scope Integration (`auxiliaries/program_scope.py`)

Pulls a program's structured scope, scope exclusions, weakness list, and
policy text from the HackerOne Hacker API v1 and turns them into a
machine-readable manifest the secretary and scan tools consult. Caches
manifests to `scope/<handle>.json`.

Framework tools:
- **`load_program_scope`** — fetch (or load cached) program scope: in-scope
  assets (typed: URL/WILDCARD/DOMAIN/CIDR/IP/ANDROID/IOS/BLOCKCHAIN with
  `max_severity` and CIA requirements), out-of-scope assets, excluded
  report categories, reportable weakness/CWE allowlist, and policy text.
  Also writes the workspace `.scope` file so `subdomain_enum` auto-filters
  against the real HackerOne scope.
- **`check_scope`** — test whether a target is inside the program's
  authorised scope *before* running any scanner. Out-of-scope asset matches
  always win over in-scope wildcards.
- **`check_reportable`** — test a candidate finding's category/CWE against
  the program's excluded categories and weakness allowlist before filing, to
  avoid burning HackerOne reputation on N/A reports.
- **`program_hacktivity`** — fetch the program's hacktivity feed for
  duplicate-checking. Works without credentials (public feed); includes a
  behavioral guard against silent filter-ignoring.
- **`search_programs`** — keyword search ACROSS the boards' program listings
  (HackerOne authed index, Intigriti PAT list; Bugcrowd exact-handle probe —
  that lane has no public listing API). Rows carry platform/handle/name and
  bounty-relevant flags (`offers_bounties`, per-asset eligibility, tiers);
  `with_assets=True` pulls each match's manifest for a compact asset + bounty
  summary. Also exposed operator-side as `scope search <kw>` in the Tool
  REPL. Dollar bounty tables are not structured on any lane — they live in
  each program's policy prose.

**Authentication:** The structured-scope endpoints require a platform API
token. HackerOne uses Basic auth — set `H1_API_USERNAME` and `H1_API_TOKEN`
in `.env`. `program_hacktivity` works without credentials.

**Intigriti support:** `program_scope.py` also pulls Intigriti program scope
and hacktivity via `INTIGRITI_USERNAME` + `INTIGRITI_API_TOKEN`; manifests
cache to `scope/intigriti_<handle>.scope`.

### Memory Service (`memories.py`)

ChromaDB-backed persistent, namespaced vector memory for cross-harness
recall. Supports keyword search and vector similarity recall, with
session-scoped filtering. Exposed both as `@framework_tool` methods and via
the API gateway. The `findings` namespace stores lightweight pointers to
reported findings.

### Session Manager (`utils/session_manager.py`)

Process-local singleton holding live connection objects (SSH clients, MSF
sessions) keyed by `session_id`. Tools register connections on open and
retrieve them for follow-up commands without re-authenticating. Includes
stale-session cleanup.

### Session Handles (`utils/handles.py`)

Typed session handles (`kind:session_id` strings) that tools declare via
`@framework_tool(..., accepted_handle_kinds=[...])`. The secretary validates
any `handle` argument's kind against the tool's accepted set before
execution, preventing cross-namespace misuse (e.g. passing an SSH handle to
an MSF tool).

### OOB Collaborator (`listeners/collaborator.py`)

A Burp Collaborator analog: multi-protocol listener catching blind SSRF,
blind XSS, and other OOB callbacks. HTTP on TCP 80, HTTPS on TCP 443
(self-signed cert), and DNS on UDP 53 — all on one host. The payload ID
rides in the subdomain; `collab_generate` produces a unique callback
URL/DNS name and `collab_poll` returns correlated events. Requires root for
ports 80, 443, and 53.

### SQLite Database (`utils/sessions.py`)

Tracks targets, sessions, payloads, and notes in `ids.db`. Schema defined
in `schema.md`. The findings table shares this database.

### API Gateway (`api_gateway.py`)

FastAPI server (port 5000) exposing:
- `GET /health` — framework health check
- `POST /tools/execute` — semantic tool lookup + execution
- `POST /tools/search` — semantic tool search (no execution)
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall
- `POST /mcp` — streamable-HTTP MCP endpoint (`tools/list` + `tools/call`)

Also serves MCP (Model Context Protocol) handlers for tool listing and
execution. If `GATEWAY_API_KEY` is set, every request is authenticated;
otherwise the gateway runs in unauthenticated dev mode.

## Quick Start

### Prerequisites

- Python 3.12+ (3.13 supported)
- [Ollama](https://ollama.ai) running with `nomic-embed-text` and a chat
  model (default: `hf.co/unsloth/GLM-4.7-Flash-GGUF:Q3_K_M`)
- ChromaDB server (default: `localhost:9000`; used by the tool registry —
  the memory service `memories.py` uses its own embedded store at
  `.memory/chroma`)
- External CLI tools as needed (see [External Dependencies](#external-dependencies)):
  Nmap, Masscan, OWASP Amass, OWASP ZAP, Radare2, Metasploit Framework, ffuf,
  Hydra, sqlmap, searchsploit
- HackerOne API token (optional, for scope integration)
- Root or `CAP_NET_RAW` (optional, for raw SYN scanning and the OOB
  collaborator's privileged ports)

### Configuration

Environment variables (copy `.env.example` to `.env` and fill in real
values; see `.env.example` for the full key list):

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | LAN fallback (`10.0.0.x`) | Ollama API endpoint — set explicitly in `.env` |
| `CHROMA_HOST` | `localhost` | ChromaDB host |
| `CHROMA_PORT` | `9000` | ChromaDB port |
| `SECRETARY_MODEL` | `hf.co/unsloth/GLM-4.7-Flash-GGUF:Q3_K_M` | LLM model for the tool secretary (non-thinking chat model recommended) |
| `MSGRPC_PASSWORD` | — | Metasploit RPC password |
| `MSF_RPC_PORT` | `55553` | Metasploit RPC port |
| `MCP_ENDPOINT` | `http://127.0.0.1:55553` | Metasploit MCP sidecar endpoint |
| `BRAIN_DISPATCH_TIMEOUT` | `600` | Brain socket dispatch timeout (seconds) |
| `BRAIN_SCAN_DIRS` | `auxiliaries,listeners,payloads` | Directories the Brain scans at startup |
| `WORKSPACE_ROOT` | current directory | Root for tool path resolution |
| `GATEWAY_API_KEY` | — | API gateway authentication key (unset = dev mode) |
| `ZAP_HOST` | `127.0.0.1` | ZAP daemon API host |
| `ZAP_PORT` | `8090` | ZAP daemon API port |
| `ZAP_API_KEY` | — | ZAP daemon API key |
| `H1_API_USERNAME` | — | HackerOne API username (Basic auth) |
| `H1_API_TOKEN` | — | HackerOne API token |
| `COLLAB_DOMAIN` | `oob.lab` | OOB collaborator domain |
| `COLLAB_HTTP_PORT` | `80` | OOB collaborator HTTP port |
| `COLLAB_HTTPS_PORT` | `443` | OOB collaborator HTTPS port |
| `COLLAB_DNS_PORT` | `53` | OOB collaborator DNS port |
| `R2_BINARY_TARGETS_ROOT` | `binaries/` | Radare2 binary drop folder |
| `WORDLISTS_ROOT` | `/usr/share/wordlists` | Wordlist tree root |
| `SECRETARY_MAX_APPROVAL_ROUNDS` | `5` | Max approval rounds per secretary turn |
| `SECRETARY_TURN_TIMEOUT` | `600` | Secretary turn wall-clock cap (seconds) |
| `SQLMAP_TIMEOUT` | `1800` | sqlmap scan wall-clock cap (seconds) |
| `ROUTER_MAX_DISTANCE` | `1.1` | API-path semantic-match refusal threshold (ChromaDB L2; lower = stricter) |
| `ZAP_PROXY_BIND` | `0.0.0.0` | ZAP browser-proxy bind address (daemon API ACL stays loopback) |
| `ZAP_XMX` | `512m` | ZAP daemon JVM heap size |
| `INTIGRITI_USERNAME` | — | Intigriti platform username (scope integration) |
| `INTIGRITI_API_TOKEN` | — | Intigriti API token (scope integration) |

### Running

```bash
# Install dependencies
pip install -r requirements.md

# Index tools into the vector registry
python -m daharness.core

# Clear and re-index
python -m daharness.core --clear

# Interactive chat with the secretary (starts all sidecars: Brain, ZAP, MSF MCP, API gateway)
python bootstrap.py            # interactive (indexes + chat)
python bootstrap.py --daemon   # background services only (no chat loop)

# Run tests
pytest tests/
```

In both modes, `bootstrap.py` starts the Brain sidecar, the ZAP daemon, the
Metasploit MCP sidecar, and the API gateway (with MCP handlers). The
Metasploit MCP sidecar is also vectorized, but the full index is only
searchable from the secretary chat loop, and then executed with human approval.

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
- **Scope compliance:** `check_scope` gates every scan against the loaded
  HackerOne program scope before execution — out-of-scope assets are
  rejected, and explicit out-of-scope entries override in-scope wildcards.
- **Reportability gate:** `check_reportable` tests candidate findings
  against the program's excluded categories and weakness allowlist before
  filing, preventing N/A or spam-grade reports.
- **Path confinement:** local script execution is restricted to
  `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`, `listeners/`, `utils/`,
  `encoders/`).
- **No import at discovery time:** static analysis uses `ast` only — hostile
  or broken code cannot execute during indexing.
- **Timeouts:** Brain dispatch and subprocess execution are bounded to
  prevent hanging the conversation loop. Long-running CLI tools use the
  background job pattern so the secretary turn is never held open.

### Legal Addendum — Local Models Only for Pentesting

> **WARNING — DATA EGRESS RISK.** This framework orchestrates offensive
> security tools (port scanners, web spiders, active scanners, exploit
> frameworks) against live targets. The tool secretary is an LLM that
> reads target responses, HTTP bodies, command output, and findings to
> reason about next steps. **If the secretary model is hosted on a
> third-party cloud API (OpenAI, Anthropic, Google, or any provider
> outside your own infrastructure), every tool output it processes is
> transmitted to that provider's servers.** This includes response bodies
> from scanned targets, extracted credentials, session tokens, internal
> IP addresses, error messages, and any other data the tools surface.
>
> Sending this data to a third party constitutes **unauthorized data
> egress** from the target's environment and may violate:
>
> - The target organisation's acceptable-use / data-handling policies.
> - Bug bounty program rules of engagement (many programs explicitly
>   prohibit sending target data to third-party services).
> - Data protection regulations (GDPR, CCPA, HIPAA, and equivalents)
>   when the target handles personal, financial, or health data.
> - Non-disclosure agreements, engagement letters, or ROE scope terms.
>
> **You MUST use a locally-hosted model** (e.g. via Ollama, llama.cpp, or
> a self-managed vLLM instance on infrastructure you control) as the
> secretary. Set `OLLAMA_BASE_URL` to a loopback or LAN address. Do not
> point the framework at a cloud-hosted LLM API for any engagement
> involving live third-party targets.
>
> The framework's default `SECRETARY_MODEL` points to a locally-served
> GGUF model. Do not override it with a cloud model for pentesting work.
> If you are testing against your own infrastructure in an isolated lab
> with no real user data, the egress risk is your own to assess — but
> the default configuration assumes local models precisely to keep
> target data on-box.
>
> **Using a cloud-hosted LLM with this framework against a target you do
> not own is a data-handling decision you are solely responsible for.
> The framework authors assume no liability for data egress caused by
> misconfigured model endpoints.**

## Project Layout

```
daharness/              Tool secretary agent + semantic registry (core package)
  agent.py              Secretary agent factory
  registry.py           Discovery and semantic search API
  executor.py           Standalone execution helpers
  findings.py           SQLite-backed findings store (FindingStore)
  models.py             ToolManifest + Finding pydantic models
  _param_docs.py        Parameter-docstring introspection for tool manifests
  core.py               Backwards-compat shim / CLI entry point
constants.py            @framework_tool decorator + TransportType enum
bootstrap.py            Daemon entry point; launches all sidecars (Brain, ZAP, MSF MCP, API)
api_gateway.py          FastAPI control panel + MCP server (port 5000)
memories.py             ChromaDB-backed namespaced vector memory
listeners/
  thebrain.py           Unix socket sidecar + function registry
  listening.py          TCP listener with Brain integration
  collaborator.py       OOB callback listener (HTTP/HTTPS/DNS, Burp Collaborator analog)
  raw_scan.py           SYN scanner wrapper (C++ plugin)
  plugins/              C/C++ shared objects (frameit, raw_scan)
payloads/
  metasploiting.py      Metasploit RPC client (search/execute/sessions)
  ffuf.py               ffuf web fuzzing (launch/poll/cancel)
  hydra.py              Hydra credential brute-force (launch/poll/cancel)
  sqlmap.py             sqlmap SQL injection (launch/poll)
  searchsploiting.py    searchsploit (ExploitDB) lookup
  fastcgi.py            FastCGI/PHP-FPM exploitation
  wordlists.py          Wordlist discovery
  plugins/              Payload listener (C++)
auxiliaries/
  nmap.py               Nmap scanner
  masscan.py            Masscan fast port scanner (launch/poll/cancel)
  amass.py              OWASP Amass v5 subdomain enumeration
  zap.py                OWASP ZAP HTTP API client
  radare2.py            Radare2 static binary analysis
  program_scope.py      HackerOne scope integration
  impacket_suite.py     Impacket: SMB/psexec/wmiexec/atexec/secretsdump
  ssh_exec.py           SSH batch command execution
  smb_scanner.py        SMB null session scanner
  cert_tools.py         TLS cert generation for collaborator
  framework_status.py   Framework health check
utils/
  findings.py           Finding report/render/close/supersede tools
  paramiko_client.py    Persistent SSH tools
  session_manager.py    Singleton for live session objects
  sessions.py           SQLite database (targets/sessions/notes/findings)
  log_reader.py         Brain/MSF log reading and streaming
  packetcraft.py        Scapy packet crafting (craft_*/send/sniff/dissect/modify)
  memory_tools.py       remember_text/recall_text vector memory tools
  background_job.py     Shared background-job launch/poll helper
  handles.py            Session handle formatting/parsing/validation
  wordlists.py          Wordlist utilities
  plugins/              C/C++ shared objects + TLS certs
encoders/               Encoder plugins (C/C++)
binaries/               Radare2 binary drop folder (gitignored)
scope/                  Cached HackerOne program scope manifests (gitignored)
findings_md/            Rendered markdown finding reports (gitignored)
chroma-data/            ChromaDB persistence (gitignored)
tests/                  pytest suite for registry + secretary flows
schema.md               SQLite database schema
AGENTS.md               AI agent development guide
docs/                   Target dossiers (local-only, gitignored)
ledger_archive/         Rotated-out ledger snapshots (local-only, gitignored)
dockered/               Docker workbench: compose, Dockerfiles, start_gateway.py
.env.example            Configuration template (copy to .env; .env is not tracked)
```
