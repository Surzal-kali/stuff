# Modular Security Framework

A headless, MCP-capable orchestration harness for security research and
bug-bounty automation. A small local LLM (the "tool secretary") semantically
searches a vector-indexed tool registry, selects the right module for a
natural-language request, and executes it. Inside the harness, every
execution pauses for human-in-the-loop sign-off: the operator sees the full
tool manifest and arguments before approving, and only an approved tool
actually runs. (This gate is an internal-harness feature — the API gateway
and MCP lanes bypass it unless the harness you're integrating adds its own
approval layer.) Large tool outputs stay out of the model's context window
via a result-projection middleman (`full` | `digest` | `page` — `digest` by
default) that stores the raw evidence in a durable scratch store and hands
the model a compact envelope instead.

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
`ornith-1.5:35b`) acts as a conversational agent with two tools:

1. **`search_tools`** — semantic search over the tool registry (ChromaDB,
   `nomic-embed-text` embeddings, HNSW cosine similarity). Returns full tool
   manifests.
2. **`execute_tool`** — runs a surfaced tool. It is declared
   `requires_approval=True`, so the run **always pauses** with pydantic-ai's
   `DeferredToolRequests`: the confirmer shows the operator the full
   manifest + arguments and execution proceeds only on approval
   (`run_secretary()` resumes the loop with the same `deps` + message
   history), capped at `SECRETARY_MAX_APPROVAL_ROUNDS` rounds per turn.
   After an approved execution a framework-log tail (Brain/MSF) can be
   appended to the result for visibility
   (`POST_EXECUTION_LOGS`: `off` | `failures` | `always`, default
   `failures`), and the result passes through the projection middleman
   before it enters context (see
   [Result Projection](#result-projection-utilsresult_projectionpy)).

   This gate is internal to the secretary lane — tool calls that arrive
   through the API gateway or the MCP endpoint skip it entirely.

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
- **`auxiliaries/archived_urls.py`** — **BRAIN_DISPATCH**: Passive archived-URL discovery via the Wayback Machine CDX API (bounty-relevant triage: interesting files, parameterized URLs)
- **`auxiliaries/cors_probe.py`** — **BRAIN_DISPATCH**: CORS posture + security-header audit (attacker-controlled `Origin` reflection and `null`-origin checks) via the per-hop scope-gated HTTP client
- **`auxiliaries/db_client.py`** — **BRAIN_DISPATCH**: Direct-database connect + enumerate with KNOWN credentials (MySQL via pymysql, PostgreSQL via pg8000) — deliberately not the injection lane, which is sqlmap's
- **`auxiliaries/dns_lookup.py`** — **BRAIN_DISPATCH**: Forward/reverse DNS resolution feeding the scope workflow (IP blessing; not scope-gated — it never touches the target)
- **`auxiliaries/ftp_recon.py`** — **BRAIN_DISPATCH**: FTP/SFTP recon and transfer (banner, anonymous check, listings, authenticated get/put)
- **`auxiliaries/framework_status.py`** — **BRAIN_DISPATCH**: Framework operational health check (Brain, Ollama, ChromaDB, ZAP, findings DB)
- **`auxiliaries/playwright_recon.py`** — **BRAIN_DISPATCH**: Scope-gated rendered-DOM recon (client for the Playwright sidecar)
- **`auxiliaries/playwright_sidecar.py`** — **Service**: Headless-Chromium sidecar enforcing the operator-armed scope gate at the browser request-routing layer (opt-in via `PLAYWRIGHT_SIDECAR=1`)
- **`auxiliaries/ssrf_probe.py`** — **BRAIN_DISPATCH**: Parametric SSRF fuzzer that grades responses and out-of-band callbacks (optionally the collaborator's public redirect endpoint)
- **`auxiliaries/tls_info.py`** — **BRAIN_DISPATCH**: TLS certificate + protocol posture inspection (subject/SANs, versions, ciphers, expiry runway)
- **`auxiliaries/web_login_brute.py`** — **BRAIN_DISPATCH**: Session-aware web-login brute-forcing for CSRF-protected form endpoints (token reuse per session)
- **`auxiliaries/web_probe.py`** — **BRAIN_DISPATCH**: Concurrent web-surface prober — turns open ports into live HTTP intel (status, title, stack fingerprints) in one envelope
- **`auxiliaries/web_session.py`** — **BRAIN_DISPATCH**: Stateful HTTP lane — `session_get`/`session_post`/`session_request`/`session_upload` carry cookies + CSRF tokens from the universal jar through every scope-gated hop (Django-style login flows end-to-end; `session_upload` is the multipart delivery step of the msfvenom lane; see [Universal Cookie Jar](#universal-cookie-jar-utilscookie_jarpy))
- **`payloads/metasploiting.py`** — **BRAIN_DISPATCH / MCP_RPC**: Metasploit module search, execution, session polling, interaction
- **`payloads/msfvenom_tools.py`** — **BRAIN_DISPATCH**: msfvenom payload generation into `dropbox/` (presets per target stack, menu browser, artifact listing) — the file-upload lane's step 1; `start_handler=True` starts the catch listener
- **`payloads/ffuf.py`** — **BRAIN_DISPATCH**: ffuf web fuzzing: directories, files, vhosts, parameters (launch/poll/cancel)
- **`payloads/hydra.py`** — **BRAIN_DISPATCH**: Hydra credential brute-force / password-spray (launch/poll/cancel)
- **`payloads/sqlmap.py`** — **BRAIN_DISPATCH**: sqlmap SQL injection detection (launch/poll with injectable verdict parsing)
- **`payloads/searchsploiting.py`** — **BRAIN_DISPATCH**: searchsploit (ExploitDB) lookup for known exploits
- **`payloads/fastcgi.py`** — **BRAIN_DISPATCH**: FastCGI/PHP-FPM exploitation (raw request + php://input RCE chain)
- **`payloads/hash_crack.py`** — **BRAIN_DISPATCH**: john the Ripper + hashcat password cracking (hash-string mode suggestion; `run_*`/`*_status`/`*_show` background-job triplets)
- **`payloads/js_recon.py`** — **BRAIN_DISPATCH**: Static JavaScript recon — API routes and secrets extracted from pages and bundles (no browser, no heavy deps)
- **`payloads/wordlists.py`** — **BRAIN_DISPATCH**: Query-based wordlist discovery over the source tree including Kali's symlinked folders (feeds ffuf/hydra)
- **`utils/findings.py`** — **BRAIN_DISPATCH**: Report, render, close, and supersede structured security findings
- **`utils/paramiko_client.py`** — **BRAIN_DISPATCH**: Persistent SSH (connect/exec/shell/close) + one-shot mode
- **`utils/packetcraft.py`** — **BRAIN_DISPATCH**: Scapy packet crafting: craft_*(icmp/tcp/udp/arp/vlan/dhcp/dns/mdns/http), send_packet, send_and_receive_packet (sr1/srp1: fires a probe and captures its reply in one gated call), sniff_packets, dissect_packet, modify_packet, save/load pcap
- **`utils/log_reader.py`** — **BRAIN_DISPATCH**: Read/stream Brain and MSF logs
- **`utils/memory_tools.py`** — **BRAIN_DISPATCH**: Namespaced vector memory (remember_text/recall_text)
- **`utils/crypto_kit.py`** — **BRAIN_DISPATCH**: Offline crypto/encoding workbench — decode, identify, and attack encoded blobs (Base64/JSON cookies, JWTs, unsalted hashes; zero network)
- **`utils/cookie_jar.py`** — **BRAIN_DISPATCH**: Universal cookie jar + token vault — durable, cross-process SQLite store of cookies/CSRF tokens/bearer strings every web tool shares (state lives on disk, so the Brain, in-process lane, REPL, and gateway all see the same jar; see [Universal Cookie Jar](#universal-cookie-jar-utilscookie_jarpy))
- **`utils/gated_http.py`** — **Helper**: Per-hop scope-gated HTTP (closes the 302-to-out-of-scope bypass); used by cors_probe, ssrf_probe, web_probe, js_recon; `gated_get`/`gated_request` accept an optional caller-managed `requests.Session` (the stateful web_session lane rides this hook without changing default stateless behavior)
- **`utils/scratch_store.py`** — **Store**: Durable, ownership-scoped scratch storage backing digest/page result projection (see [Result Projection](#result-projection-utilsresult_projectionpy))
- **`utils/background_job.py`** — **Helper**: Shared background-job launch/poll helper for long-running CLI tools
- **`utils/handles.py`** — **Helper**: Session handle formatting, parsing, and validation
- **`listeners/listening.py`** — **BRAIN_DISPATCH**: TCP listener with Brain event forwarding
- **`listeners/collaborator.py`** — **BRAIN_DISPATCH**: OOB callback listener (Burp Collaborator analog): HTTP/HTTPS/DNS on one host
- **`listeners/raw_scan.py`** — **BRAIN_DISPATCH**: Raw SYN port scanner (C++ plugin via ctypes)
- **`listeners/brain_control.py`** — **BRAIN_DISPATCH**: Visibility + kill switch for Brain-side tool executions (`list_tool_executions` / `kill_tool_execution`)
- **`listeners/execution_tracker.py`** — **Brain-side**: Execution tracker state shared with `thebrain.py` (live/tracked executions, zombie kill switch)
- **`memories.py`** — **BRAIN_DISPATCH**: Namespaced vector memory (remember/search/recall/get/forget)

### Tool Categories (`daharness/tool_tags.py`)

With 150+ tools, not every tool surfaces for every reasonable phrasing. Each
tool carries category tags from a canonical 13-bucket vocabulary that are
appended to its embedded capability text (`...\n\nCategories: web.fuzz`), so a
search that uses category language ("recon", "fuzz", "brute", "packet")
surfaces the tagged tools even when the tool's own prose never used that word.

- Vocabulary (`CANONICAL_TAGS`): `recon.subdomain`, `recon.web`,
  `recon.dns-certs`, `recon.scope`, `web.fuzz`, `web.probe`, `web.auth`,
  `exploit.web`, `exploit.msf`, `brute.crack`, `net.raw`, `net.services`,
  `infra` (infra = main framework tooling and internals; net.services =
  non-HTTP network-service tooling — SSH/SMB/FTP access, remote exec, secrets
  dump, callback listeners — and the landing bucket for tool-nursery
  candidates from model suggestions during lab runs).
- Bulk assignment for existing tools: the `TOOL_TAGS` map in
  `daharness/tool_tags.py`, keyed by exact tool_id — one reviewable table.
- New tools: tag inline via the decorator — `@framework_tool(doc, ...,
  tags=["web.fuzz"])` (decorator tags win over the map for the same id).
- Tags persist in ChromaDB metadata (`tags_json`), surface in
  `describe_manifest` (the secretary sees the category beside every search
  hit), and a tag change re-embeds the tool automatically on the next
  `python -m daharness.core` (the doc changes, which is the change signal).
- Non-canonical tags are warned about (bootstrap/reindex log) but kept.
- All registry tools are tagged (`net.services` closed
  the non-HTTP-service gap; port scanners stay `net.raw` — the scan lane —
  while `net.services` is for interacting with a discovered service).

### Background Job Pattern

Long-running CLI tools (nmap, masscan, amass, ffuf, hydra, sqlmap) use the
shared `utils/background_job.py` helper: `launch_job` starts a detached
`subprocess.Popen`, writes a JSON sidecar to disk (so polls survive a
harness restart), starts a reaper thread for the wall-clock cap, and
returns a `job_id` immediately — the secretary turn is not held open.
`poll_job` reads the log, checks liveness, tails recent lines, and returns
a structured `status: "running" | "done"` dict. Each tool pair follows the
`run_*` / `*_status` / `*_cancel` shape.

Poll verdicts are bounded: ffuf's parsed findings list is capped at
`FFUF_MAX_FINDINGS` (default 10000, most interesting status codes kept
first) because a catch-all target — an app that redirects every path, so
every wordlist word "hits" — can otherwise produce a verdict larger than
the Brain's 10 MiB wire-frame guard (`MAX_MESSAGE_SIZE`,
`listeners/thebrain.py`), and the reply dies on the socket read
("brain dispatch failed: declared message length ... exceeds max"). The
true count is reported via `findings_total` / `findings_truncated`, and
the full result set always remains in the job's `-o` JSON output file
(`meta.output_file`).

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
| --- | --- | --- |
| **Nmap** | `auxiliaries/nmap.py` | Port/service scanning; NSE script library accessible via `--script` in options (`nmap_scripts` lists the 600+ installed scripts) |
| **Masscan** | `auxiliaries/masscan.py` | Fast async port scanning; requires root or `CAP_NET_RAW` |
| **OWASP Amass** | `auxiliaries/amass.py` | Subdomain enumeration (v5+; passive mode by default) |
| **OWASP ZAP** | `auxiliaries/zap.py` | Web app scanning; launched in `-daemon` mode by `bootstrap.py` |
| **Radare2** | `auxiliaries/radare2.py` | Static binary analysis; `r2pm -ci r2ghidra` for decompilation |
| **jadx** | `auxiliaries/jadx.py` | APK/dex/jar decompilation (`apk/` drop folder, cached workspaces, grep/read over decompiled sources) |
| **Metasploit Framework** | `payloads/metasploiting.py` | MSF RPC integration (MCP sidecar started by `bootstrap.py`) |
| **msfvenom** | `payloads/msfvenom_tools.py` | Payload artifact generation for upload testing (`dropbox/` output; handler start built in) |
| **ffuf** | `payloads/ffuf.py` | Web content fuzzing |
| **Hydra** | `payloads/hydra.py` | Credential brute-force |
| **sqlmap** | `payloads/sqlmap.py` | SQL injection detection |
| **searchsploit** | `payloads/searchsploiting.py` | ExploitDB local lookup |
| **Impacket** | `auxiliaries/impacket_suite.py` | Windows post-exploitation (SMB, psexec, wmiexec, atexec, secretsdump) |
| **Scapy** | `utils/packetcraft.py` | Packet crafting, send, send-and-receive probes (sr1/srp1), sniffing (Python library) |
| **Paramiko** | `utils/paramiko_client.py`, `auxiliaries/ssh_exec.py` | SSH client (Python library) |
| **john the Ripper** | `payloads/hash_crack.py` | Password cracking (`run_john` / `john_status` / `john_show`, background-job pattern) |
| **hashcat** | `payloads/hash_crack.py` | Password cracking (`run_hashcat` / `hashcat_status` / `hashcat_show`, background-job pattern) |

### OWASP ZAP

1. Install ZAP (`sudo apt install zaproxy` on Debian/Ubuntu/Kali — the plain
   `zap` package name does not resolve — or download from the official
   site).  Kali's package installs `/usr/bin/zaproxy` / `/usr/bin/owasp-zap`
   (both wrappers for `/usr/share/zaproxy/zap.sh`); the plain-ZAP layout
   (`zap` on PATH or `/usr/share/zap/zap.sh`) also works. For anything else,
   set `ZAP_BIN` to the launcher path.
2. The launcher is resolved automatically in the order: `$ZAP_BIN` → `zap` →
   `zaproxy` → `owasp-zap` (all PATH) → `/usr/share/zaproxy/zap.sh` →
   `/usr/share/zap/zap.sh`.
3. The framework launches ZAP in `-daemon` mode (loopback-only API) and
   manages its configuration automatically. The home directory is pinned to
   `.zap_home/` in the workspace root. ZAP is never run as root — the
   launcher drops to the original user if the framework was started with
   `sudo`. The ZAP *browser-proxy* listener binds `ZAP_PROXY_BIND`
   (default `0.0.0.0`) for upstream proxying; only the daemon's API is
   restricted to loopback.
4. Set `ZAP_API_KEY` in `.env`; it is sent as the `apikey` query parameter on
   every API call.

### Playwright Rendered-DOM Recon Sidecar

The scope-enforcing headless-Chromium sidecar for JS-heavy / SPA recon
(`auxiliaries/playwright_sidecar.py` + `auxiliaries/playwright_recon.py`).
It gates **navigations + fetch/XHR/websockets** through the operator-armed
scope gate at the browser request-routing layer; passive subresources
(img/css/font/media/script) are allowed from anywhere so pages render.

1. Install the Python package and the Chromium browser binary:

   ```bash
   ./venv/bin/pip install playwright
   # IMPORTANT: install the browser INTO THE REPO (gitignored) so the path
   # is workspace-relative and root can find it. The framework runs as root
   # (HOME=/root), where the default ~/.cache/ms-playwright is empty.
   PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.pw-browsers" \
     ./venv/bin/python -m playwright install chromium
   ```

   The browser lands in `.pw-browsers/` (gitignored). The sidecar
   auto-resolves it from `$WORKSPACE_ROOT/.pw-browsers` (falling back to
   this module's repo root) and sets `PLAYWRIGHT_BROWSERS_PATH` at import —
   so it works whether the framework was launched as root or your user.
2. The framework runs as root, so Chromium is launched with `--no-sandbox`
   (the setuid sandbox cannot run as root and would hang the launch).
   Sandbox isolation is kept when running non-root (lab/dev).
3. Enable the sidecar at launch with `PLAYWRIGHT_SIDECAR=1` (off by
   default). Tools: `playwright_fetch` (one-shot rendered-DOM envelope),
   `playwright_crawl` / `playwright_crawl_status` /
   `playwright_crawl_stop` (bounded launch/poll crawl). If the sidecar is
   down, the tools return a clear "not reachable" error — never a faked
   result. `challenge_detected` flags Cloudflare-class interstitials
   honestly (vanilla only — no stealth patches).
4. Auth'd crawling: set `PLAYWRIGHT_STORAGE_STATE` to a Playwright
   `storageState` JSON path (env / deploy-time injection only — never a
   tool argument).

### Metasploit Framework

1. Install Metasploit Framework.
2. Set `MSGRPC_PASSWORD` and `MSF_RPC_PORT` in `.env`.
3. `bootstrap.py` starts the MSF MCP sidecar (`msfrpcd`) automatically and
   vectorizes discovered modules into the tool registry.

### Docker deployment (`dockered/`)

A containerized workbench lives in `dockered/` and bind-mounts the live
source tree (code edits on the host need no rebuild). Start with:

```bash
cd dockered
docker rm -f chroma          # remove a legacy standalone chroma container if present
docker compose up -d --build
```

Services:

| Service | Host port | Notes |
| --- | --- | --- |
| ChromaDB (`chroma`) | `9000` | Reuses the existing `chroma-data/` volume |
| Open Terminal | `8000` | Codebase workbench: agent shell + file browser; hosts the framework gateway + Brain sidecar |
| Open WebUI | `3000` | Chat front end; calls the framework via the tool wrappers in `owui-tools/` |

**Open Terminal** is the codebase workbench. The framework source is
bind-mounted at `/opt/framework` (host `..` → container). The
Dockerfile (`dockered/open-terminal.Dockerfile`) bakes in the Python venv,
Go-built CLI tools (ffuf, amass), radare2, jadx, searchsploit, and
apt-available security tools; the framework source is never copied.

**Open WebUI** is the chat front end. It reaches the framework through the
Open WebUI tool wrappers in `owui-tools/owui-wrapper.py` (v0.3.2): five
tools — `framework_search_tools`, `framework_run_tool`,
`framework_scratch_search`, `framework_memory_search`, `framework_health` —
that call the gateway's `/tools/search`, `/tools/execute`, `/scratch/search`,
`/memory/search`, and `/health` routes with per-chat session isolation (Brain
sessions auto-named
`owui-<model>-<chat>`). Install the wrapper as an Open WebUI tool and point
its `gateway_url` valve at `http://localhost:6000` (from the host; the
wrapper default targets `http://open-terminal:6000` from inside the
`open-webui` container). The approval gate is an internal-harness feature
and does not exist in this lane — tool calls execute directly through the
gateway, and the same applies to the MCP server. Add an approval layer in
your own integrating harness if you need one there.

Keys come from `dockered/.env`: `GATEWAY_API_KEY`,
`OPEN_TERMINAL_API_KEY`.

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

### Tool REPL (`tool_repl.py`)

The operator's console for exercising framework tools directly — it
bypasses the secretary LLM entirely: pick a tool, supply arguments, see
the raw result. Use it to isolate tool-execution problems from
model-reasoning problems, to arm/control the scope gate, and to
smoke-test tools after adding or editing modules. `run` dispatches
through the same executor as the Brain, so the armed scope gate applies
here too — the REPL is also where refusals can be tested safely.

Launch: `python tool_repl.py` (interactive). One-shot modes:
`python tool_repl.py run <tool_id> [--flag value ...]` (or
`run <tool_id> --json '{...}'`, or bare `run <tool_id>` = safe defaults),
`info <tool_id>`, `sweep`, `search <query>`.

Interactive commands:

    list [filter]        print discovered tool manifests (substring filter)
    info <tool_id>       full manifest: params, defaults, embedding blurb
    resolve <tool_id>    import the callable; print signature + docstring
    run <tool_id> [--flag value ...] | --json '{...}'
                         execute a tool; shlex quoting honoured; args
                         type-coerced from the tool's own manifest schema;
                         bare `run` falls back to the tool's SAFE_ARGS
                         defaults (see safe-args)
    sweep [--force]      run EVERY discoverable tool with safe args and a
                         summary table; tools needing a live service are
                         skipped unless --force
    safe-args [<id>]     show the SAFE_ARGS table (or one tool's entry)
    search <query>       semantic search (needs ChromaDB + Ollama);
                         rendered worst-match-first so rank #1 prints
                         LAST, right above the prompt
    scope ...            scope-gate control — see the next section
    reindex              re-discover tools after adding/editing modules
                         (manifests only, no ChromaDB re-embed)
    ipython              IPython shell preloaded with the registry,
                         manifests, and quick_run(tool_id, **kwargs)
    help / quit

Input UX: prompt_toolkit ghost text plus a tiered completer — commands →
tool IDs → `--flag` names from the chosen tool's schema → scope
subcommands and their flags. History persists in `~/.tool_repl_history`.
The prompt carries a `✓` prefix while the scope gate is ARMED (sends
gated); it disappears when disarmed.

Two refresh layers, easy to confuse: REPL `reindex` re-runs tool
discovery in-process (manifests + direct `run` see code edits
immediately), while `python -m daharness.core` rebuilds the vector
registry — semantic `search` and the secretary keep seeing the OLD
embeddings until that re-embed runs (and the Brain is restarted).

### Scope Gate — Operator-Armed (`utils/scope_gate.py`)

The armed gate is a technical backstop the OPERATOR arms from the Tool
REPL — separate from `check_scope` above, which only consults a loaded
manifest. Arming/disarming is deliberately NOT exposed as an
`@framework_tool`, so the secretary model has no way to toggle or bypass
it. When disarmed (the default — lab mode) tools behave exactly as
before.

    scope on <handle> [--platform P] [--no-strict]   # arm (refuses blind: needs a cached manifest)
    scope status                                      # armed state, asset counts, manifest age
    scope add-ip <ip> [<hostname>]                    # bless a resolved in-scope IP (CDN-safe)
    scope add-host <hostname> <ip>                    # bless a vhost hostname (IP must already be blessed)
    scope rm-ip <ip> / scope rm-host <hostname>       # revoke blessings; scope list-ips shows the allowlist

Enforcement is file-backed, not in-process: the armed state lives in
`scope/.armed_packet_scope.json` (atomic writes, mtime-checked on every
call), so a blessing written from the REPL is authoritative in every
process — a REPL change takes effect immediately inside a running Brain.

Gated calls fail CLOSED — a block raises `ScopeGateError`, which surfaces
as `Failed` on both dispatch paths (Brain socket + in-process fallback):

- **`check_send`** — packetcraft `send_packet` / `send_and_receive_packet`:
  the destination IP extracted from the crafted packet (v4/v6 dst, ARP
  `pdst`); the check runs BEFORE the probe fires.
- **`check_scan`** — nmap, masscan, ffuf, hydra, ZAP, impacket/SMB,
  raw_scan, paramiko SSH, sqlmap, fastcgi, ssh_exec, MSF dispatch:
  URL / bare host / IP / CIDR / hyphen-range / list shapes; one
  out-of-scope spec refuses the whole call.

Verdict tiers (first match wins; an out-of-scope match always beats an
in-scope wildcard):

1. **Operator allowlist** — `scope add-ip` blessings (authoritative,
   CDN-safe: the operator confirmed the IP belongs to an in-scope host).
1b. **Operator-blessed hostnames** — `scope add-host <hostname> <ip>` maps a
   vhost hostname to an ALREADY-blessed IP (for lanes whose connect target
   is the Host header, e.g. ZAP raw send). The operator asserts the mapping;
   the gate never resolves DNS for it.
2. **Manifest match** — the program's typed in-scope assets (DOMAIN/
   WILDCARD/URL for hostnames, IP/CIDR for IPs).
3. **Reverse-DNS attribution** — PTR records are attacker-settable, so an
   in-scope PTR match only auto-allows after forward-confirmation (the
   PTR name must resolve back to the scanned IP; 2s cap, fail-closed).

Strict mode (default): any unconfirmed target is REFUSED with guidance;
`--no-strict` warns instead. Broad CIDR/hyphen ranges are allowed only as
a subnet of an explicit in-scope CIDR asset; otherwise refused — disarm
(`scope off`) for lab / internal-network work.

Never gated by design: non-routable destinations (broadcast, multicast,
loopback, link-local, reserved — DHCP/mDNS probes pass), pure-L2 frames
with no routable IP, receive-only traffic (sniffing, inbound replies), and
offline tools (crafting/dissecting never touch the wire). Known residual
surfaces: the gate sees the REQUESTED target only — DNS-resolver traffic
is out of its view, and redirect-following inside scan binaries is
handled per-tool (ffuf `-r` is denylist-stripped; ZAP crawls are mirrored
by `zap_sync_scope`, which puts ZAP itself in protect mode against OOS
hops; and `utils/gated_http.py` re-validates every redirect hop that the
HTTP probe tools follow).

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

### Universal Cookie Jar (`utils/cookie_jar.py`)

Almost every web tool in the framework is a stateless one-shot — it makes
one request and throws away everything the app handed back. Middleware-managed
state (Django's CSRF dance, session cookies, bearer tokens) therefore blocks
audits at the front door: you can't even see the authenticated surface
without carrying `csrftoken` + `csrfmiddlewaretoken` + `sessionid` between
calls. Cookies and tokens are just strings, so the jar makes that state
**durable and universal**:

- **SQLite-backed** (`cookie_jar.db`, WAL): state lives on disk, so every
  lane — Brain sidecar, in-process fallback, REPL, API gateway — sees the
  same jar without any cross-process broker. Deliberately sidesteps the
  process-local limitation of the Session Manager.
- **Cookie jar** (RFC 6265 matching): domain rules honor `Domain=`-style
  dot-forms, and IP hosts never match dot-forms (a `.56.106` suffix can't
  leak a cookie onto `192.168.56.106`). Path rules apply when building
  ready-made `Cookie:` headers for non-jar-aware tools (ffuf/sqlmap/ZAP).
- **Token vault**: named token strings per host (CSRF form fields, bearer
  tokens) with latest-wins upsert. `extract_csrf_tokens()` pulls values from
  hidden inputs, `<meta>` tags, and response headers (Django, Rails,
  Laravel, ASP.NET canonical order), HTML-unescaped.
- **Hygiene**: TTL purge (default 72h via `COOKIE_JAR_TTL_HOURS`) plus
  server-expiry purge on every mutation; `COOKIE_JAR_DB` overrides the path.
- **Tools**: `jar_state`, `jar_store_cookie` (paste `a=1; b=2` strings),
  `jar_store_token`, `jar_clear`, `jar_cookie_header`.

The `session_get`/`session_post`/`session_request` lane
(`auxiliaries/web_session.py`) applies this state through
`gated_request(session=...)` — every hop still passes the operator-armed
scope gate. A Django login becomes three plain calls: `session_get /login/`
(cookie + token captured) → `session_post /login/` with credentials (form
field + `X-CSRFToken` header auto-injected, `sessionid` captured) →
`session_get /dashboard/` (authenticated).

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

**Public mode** — set `COLLAB_PUBLIC_URL` (e.g. a Tailscale Funnel endpoint
like `https://<device>.<tailnet>.ts.net`) and `collab_generate` returns
path-based PUBLIC callback URLs (`<public>/c/<id>/`) instead of lab
subdomains, and a token-gated redirect endpoint goes live at
`/r/<id>?to=<url>` → 302 (redirect-to-internal blind SSRF; `scan_ssrf`
gains a `redirect_to` param for it). Funnel walkthrough: `tailscale funnel
<COLLAB_HTTP_PORT>` (use 8080 — no root needed), public HTTPS terminates at
Tailscale and forwards plain HTTP to `127.0.0.1:<COLLAB_HTTP_PORT>`. Honest
limits: Funnel serves HTTPS only and does not expose DNS-query events, so
public mode is HTTP-callback-only (subdomain mode keeps the DNS signal).
Every callback is appended to `scope/collab_hits.jsonl` as durable
evidence (gitignored); the in-memory store is capped at 5000 entries.

### SQLite Database (`utils/sessions.py`)

Tracks targets, sessions, payloads, and notes in `ids.db`. Schema defined
in `schema.md`. The findings table shares this database.

### API Gateway (`api_gateway.py`)

FastAPI server (port **5000** on the host lane; **6000** in the container
lane) exposing:

- `GET /health` — framework health check
- `POST /tools/execute` — exact `tool_id` dispatch or semantic lookup (accepts `result_mode`: full|digest|page, default `digest`). Enforces a per-turn tool budget: with `turn_key` (e.g. `chat_id:message_id`), each turn gets `TOOL_BUDGET_PER_TURN` executions (default 10) — the last call's result carries an end-turn directive, and past-the-limit calls are refused outright (memory/findings tools stay callable so the model can report).
- `POST /tools/search` — semantic tool search (no execution)
- `POST /scratch/search` — retrieve a stored tool result from the scratch store
- `GET /scratch/list` — list recent scratch entries for an agent
- `GET /scratch/stats` — scratch store statistics
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall
- `POST /mcp` — streamable-HTTP MCP endpoint (`tools/list` + `tools/call`)

Also serves MCP (Model Context Protocol) handlers for tool listing and
execution. `POST /tools/execute` and MCP `tools/call` dispatch directly —
the internal approval gate does not exist in these lanes, so an integrating
harness that wants sign-off needs to add its own layer before calling. If
`GATEWAY_API_KEY` is set, every request is authenticated
(sent as `X-API-Key`); otherwise the gateway runs in unauthenticated dev
mode.

### Result Projection (`utils/result_projection.py`)

A middleman between `execute_tool()` and the model's context window:
`result_mode` is an execution-envelope parameter (passed alongside
`tool_id`/`arguments`, NOT a tool argument — it never reaches the tool
body). Three modes:

- **`digest`** (default for both the secretary agent and `POST
  /tools/execute`) — stores the full result in scratch, returns a compact
  per-tool-family digest + a `scratch_ref` + the retrieval instruction. The
  model is taught the retrieval move every call. Results smaller than
  `SCRATCH_SMALL_RESULT_BYTES` (default 2 KiB — handles, verdicts, IDs) pass
  through in full automatically; only genuinely large outputs (scan logs,
  hit lists) are projected out.
- **`full`** — the raw tool result passes through unchanged (also the
  default on the MCP `tools/call` lane).
- **`page`** — stores the full result in scratch, returns a bounded page of
  list results (offset/limit) + a `scratch_ref` + continuation info.

**Why this is not the parked OWUI trim filter:** the projection runs *before*
the result enters context (not after); the retrieval instruction is part of
the return (the model never guesses how to get the full output); per-tool-family
digest logic is honest because the tool knows its own output structure.

**Digest adapter registration:** tools opt in via
`@framework_tool(..., result_digest=my_digest_fn)`. The adapter takes the raw
result dict and returns `{"summary": str, "row_hint_format": str}`. Tools
without an adapter fall back to a naive head+count preview.

**Pilot adapter:** `nmap_status` — returns open port count + full port list +
host state + job_id, omitting the raw log text (retrievable from scratch).

### Scratch Store (`utils/scratch_store.py`)

Durable, ownership-scoped storage for raw tool results. NOT vector memory
(no embeddings, no semantic recall) and NOT the findings store (no lifecycle).
Deterministic, reference-keyed store the model retrieves from when it needs
the full or filtered output of a prior projected call: via the MCP
`scratch_search` tool, the gateway's `POST /scratch/search`, or the Open
WebUI `framework_scratch_search` wrapper.

- **Storage:** `scratch.db` (SQLite metadata) + `scratch-data/` (compressed JSON payloads, 0700/0600).
- **IDs:** opaque random values (`scratch:<16-hex>`), never sequential.
- **Ownership:** every entry is scoped to `agent_id`; a valid-looking ref from the wrong agent returns "not found".
- **Persistence:** entries survive a framework restart (on-disk).
- **TTL:** 24h (env `SCRATCH_TTL_HOURS`); cleanup runs on every `store()` call.
- **Caps:** per-entry 256 MiB (`SCRATCH_MAX_PAYLOAD_MB`), per-agent 1 GiB (`SCRATCH_MAX_AGENT_MB`).
- **Atomic writes:** payload written to temp → fsync → rename → metadata commit.

## Quick Start

### Prerequisites

- Python 3.12+ (3.13 supported)
- [Ollama](https://ollama.ai) running with `nomic-embed-text` and a local
  chat model (code default: `ornith-1.5:35b`; a thinking/reasoning model is
  recommended — the secretary plans through defenses and
  edge-infrastructure fingerprinting, which rewards reasoning). Swap via
  `SECRETARY_MODEL` in `.env`. The Ollama endpoint defaults to a lab-LAN
  fallback baked into `daharness/registry.py`; set `OLLAMA_BASE_URL` in
  `.env` to your own listener and keep it loopback/LAN (see
  [Safety Notes](#safety-notes)).
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
| --- | --- | --- |
| `OLLAMA_BASE_URL` | Lab LAN fallback | Ollama API endpoint — set explicitly in `.env` |
| `CHROMA_HOST` | `localhost` | ChromaDB host |
| `CHROMA_PORT` | `9000` | ChromaDB port |
| `SECRETARY_MODEL` | `ornith-1.5:35b` | LLM model for the tool secretary (thinking/reasoning chat model recommended) |
| `MSGRPC_PASSWORD` | — | Metasploit RPC password |
| `MSF_RPC_PORT` | `55553` | Metasploit RPC port |
| `MCP_ENDPOINT` | `http://127.0.0.1:55553` | Metasploit MCP sidecar endpoint |
| `BRAIN_DISPATCH_TIMEOUT` | `600` | Brain socket dispatch timeout (seconds) |
| `BRAIN_EXEC_CEILING` | `3600` | Hard cap on any single tool execution on the Brain (seconds; 0 = off) |
| `BRAIN_TOOL_EXECUTORS` | `16` | Dedicated Brain thread-pool size for sync tool execution (isolates wedged tools from the default executor) |
| `SSH_EXEC_TIMEOUT` | `300` | Per-command wall-clock cap for ssh_exec / ssh_exec_batch (seconds; 0 = unbounded). On timeout only the SSH channel is closed — the persistent session handle survives |
| `SSH_EXEC_OUTPUT_CAP` | `262144` | Max stdout bytes kept per ssh_exec command before truncation |
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
| `COLLAB_PUBLIC_URL` | *(empty)* | Public HTTPS base URL for the collaborator (e.g. Tailscale Funnel `https://<host>.ts.net`); set = public path-based callback URLs + `/r/<id>?to=` 302 endpoint live |
| `R2_BINARY_TARGETS_ROOT` | `binaries/` | Radare2 binary drop folder |
| `R2_OUTPUT_CAP` | `32768` | run_r2 output cap in bytes; head+tail truncation with omission marker (`0` disables) |
| `R2_TIMEOUT` | `120` | r2 subprocess wall-clock cap (seconds) |
| `JADX_APK_TARGETS_ROOT` | `apk/` | jadx apk drop folder |
| `JADX_BIN` | — | jadx launcher path (falls back to PATH; requires Java 11+ JRE) |
| `JADX_TIMEOUT` | `900` | jadx subprocess wall-clock cap (seconds) |
| `WORDLISTS_ROOT` | `/usr/share/wordlists` | Wordlist tree root |
| `SECRETARY_MAX_APPROVAL_ROUNDS` | `5` | Max approval rounds per secretary turn |
| `SECRETARY_TURN_TIMEOUT` | `600` | Secretary turn wall-clock cap (seconds) |
| `POST_EXECUTION_LOGS` | `failures` | Framework-log tail appended to the result after an approved execution: `off` \| `failures` \| `always` |
| `SQLMAP_TIMEOUT` | `1800` | sqlmap scan wall-clock cap (seconds) |
| `ROUTER_MAX_DISTANCE` | `1.1` | API-path semantic-match refusal threshold (ChromaDB L2; lower = stricter) |
| `SCRATCH_TTL_HOURS` | `24` | Scratch store entry TTL (hours); expired entries are cleaned up on every store call |
| `SCRATCH_MAX_PAYLOAD_MB` | `256` | Per-entry payload cap for the scratch store (MiB) |
| `SCRATCH_MAX_AGENT_MB` | `1024` | Per-agent total payload cap for the scratch store (MiB) |
| `SCRATCH_SMALL_RESULT_BYTES` | `2048` | Serialized results below this size pass through in full even under `digest`/`page` projection |
| `ZAP_PROXY_BIND` | `0.0.0.0` | ZAP browser-proxy bind address (daemon API ACL stays loopback) |
| `ZAP_XMX` | `512m` | ZAP daemon JVM heap size |
| `INTIGRITI_USERNAME` | — | Intigriti platform username (scope integration) |

### Running

```bash
# Install dependencies
pip install -r requirements.txt

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
Metasploit MCP sidecar, and the API gateway (with MCP handlers), after a
wordlist-tree preflight (`utils.wordlists.preflight_wordlists`) surfaces a
missing/empty wordlist source as a startup warning instead of a silent
ffuf/hydra failure. The Metasploit MCP sidecar is also vectorized, but the
full index is only searchable from the secretary chat loop, where executions
pause for operator approval.

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

- **Human-in-the-loop (secretary lane — always on there):** every
  secretary-driven tool execution pauses for explicit operator sign-off —
  `execute_tool` is declared `requires_approval=True`, the run halts with
  the full manifest + arguments for the operator to approve or deny, and
  only an approved execution actually runs. This gate is internal to the
  harness: the API gateway and MCP lanes dispatch directly, so an
  integrating harness must add its own approval if it wants sign-off.
- **Context hygiene:** tool results pass through the projection middleman
  (`digest` by default) before entering the model's context window — large
  outputs go to the durable scratch store intact and the model gets a
  compact envelope plus a retrieval reference (see
  [Result Projection](#result-projection-utilsresult_projectionpy)).
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
  preflight.py          Deterministic pre-dispatch validation (fail-fast args gate)
  tool_tags.py          Canonical tool category tags + TOOL_TAGS map
  core.py               Backwards-compat shim / CLI entry point
constants.py            @framework_tool decorator + TransportType enum
bootstrap.py            Daemon entry point; launches all sidecars (Brain, ZAP, MSF MCP, API)
api_gateway.py          FastAPI control panel + MCP server (port 5000 host lane / 6000 container lane)
memories.py             ChromaDB-backed namespaced vector memory
SYSTEM_PROMPT.md        "Brain of a local security lab" agent system prompt (reference)
Modelfile.md            Ollama Modelfiles for the local secretary GGUF models
listeners/
  thebrain.py           Unix socket sidecar + function registry
  listening.py          TCP listener with Brain integration
  collaborator.py       OOB callback listener (HTTP/HTTPS/DNS, Burp Collaborator analog)
  raw_scan.py           SYN scanner wrapper (C++ plugin)
  brain_control.py      list/kill Brain-side tool executions (zombie control plane)
  execution_tracker.py  Brain execution tracker state (zombie kill switch)
  plugins/              C/C++ shared objects (frameit, raw_scan)
payloads/
  metasploiting.py      Metasploit RPC client (search/execute/sessions)
  msfvenom_tools.py     msfvenom payload generation + catch handler (upload lane)
  ffuf.py               ffuf web fuzzing (launch/poll/cancel)
  hydra.py              Hydra credential brute-force (launch/poll/cancel)
  sqlmap.py             sqlmap SQL injection (launch/poll)
  searchsploiting.py    searchsploit (ExploitDB) lookup
  fastcgi.py            FastCGI/PHP-FPM exploitation
  hash_crack.py         john/hashcat password cracking (launch/poll/show + mode suggestion)
  js_recon.py           Static JS recon: routes + secrets from bundles
  wordlists.py          Wordlist discovery
  plugins/              Payload listener (C++)
auxiliaries/
  nmap.py               Nmap scanner
  masscan.py            Masscan fast port scanner (launch/poll/cancel)
  amass.py              OWASP Amass v5 subdomain enumeration
  zap.py                OWASP ZAP HTTP API client
  radare2.py            Radare2 static binary analysis
  jadx.py               jadx APK/dex decompilation (run_jadx composite + list_apk_targets)
  program_scope.py      HackerOne scope integration
  impacket_suite.py     Impacket: SMB/psexec/wmiexec/atexec/secretsdump
  ssh_exec.py           SSH batch command execution
  smb_scanner.py        SMB null session scanner
  cert_tools.py         TLS cert generation for collaborator
  framework_status.py   Framework health check
  archived_urls.py      Wayback CDX archived-URL discovery (passive recon)
  cors_probe.py         CORS posture + security-header audit
  db_client.py          Direct-database client (MySQL/PostgreSQL) for known creds
  dns_lookup.py         Forward/reverse DNS resolution (scope-workflow feeder)
  ftp_recon.py          FTP/SFTP recon + transfer
  playwright_sidecar.py Scope-enforcing rendered-DOM recon sidecar (opt-in)
  playwright_recon.py   Playwright sidecar client tools
  ssrf_probe.py         Parametric SSRF fuzzer + OOB grading
  tls_info.py           TLS certificate + protocol posture inspector
  web_login_brute.py    Session-aware web-login brute (CSRF token reuse)
  web_probe.py          Concurrent web-surface prober (ports → HTTP intel)
  web_session.py        Stateful HTTP lane (session_get/post/upload over the shared jar)
utils/
  findings.py           Finding report/render/close/supersede tools
  paramiko_client.py    Persistent SSH tools
  session_manager.py    Singleton for live session objects
  sessions.py           SQLite database (targets/sessions/notes/findings)
  log_reader.py         Brain/MSF log reading and streaming
  packetcraft.py        Scapy packet crafting (craft_*/send/send_and_receive/sniff/dissect/modify)
  memory_tools.py       remember_text/recall_text vector memory tools
  background_job.py     Shared background-job launch/poll helper
  handles.py            Session handle formatting/parsing/validation
  result_projection.py  full|digest|page context-projection middleman
  scratch_store.py      Durable scratch store for projected-out results
  crypto_kit.py         Offline decode/identify/attack crypto-encoding workbench
  cookie_jar.py         Universal durable cookie jar + token vault (SQLite)
  gated_http.py         Per-hop scope-gated HTTP (redirect-bypass blocker; caller-managed session hook)
  wordlists.py          Wordlist utilities
  plugins/              C/C++ shared objects + TLS certs
encoders/               Encoder plugins (C/C++)
binaries/               Radare2 binary drop folder (gitignored)
apk/                    jadx apk drop folder (gitignored; decompiled workspaces under apk/decompiled/<name>/)
scope/                  Cached program scope manifests + .armed_packet_scope.json gate state (gitignored)
findings_md/            Rendered markdown finding reports (gitignored)
chroma-data/            ChromaDB persistence (gitignored)
tests/                  pytest suite for registry + secretary flows
schema.md               SQLite database schema
AGENTS.md               AI agent development guide
docs/                   Target dossiers (local-only, gitignored)
ledger_archive/         Rotated-out ledger snapshots (local-only, gitignored)
dockered/               Docker workbench: compose, Dockerfiles, start_gateway.py, entrypoint
owui-tools/             Open WebUI tool wrappers (framework bridge: search/run/memory/health)
.env.example            Configuration template (copy to .env; .env is not tracked)
```
