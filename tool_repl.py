#!/usr/bin/env python3
"""Tool REPL: standalone harness for testing framework tools independently.

Bypasses the secretary LLM entirely — you pick a tool, supply arguments, and
see the raw result.  This isolates tool execution problems from model reasoning
problems so you can tell whether a tool actually works or if the model is just
calling it wrong.

Modes:
  interactive       (default) — REPL prompt: list, search, run, info, sweep, quit
  run <id> [--flag val ...]   — one-shot: run a tool with --flag value args
  run <id> --json '{...}'     — one-shot: run a tool with JSON args (fallback)
  sweep [--force]             — run every discoverable tool with safe/no-op args
  info <id>                   — show a tool's manifest without running it
  search <query>              — semantic search (needs ChromaDB + Ollama);
                                best match prints LAST, nearest the prompt

Argument parsing uses the tool's own parameter schema (from the manifest
discovered at startup) for type coercion — no hardcoded type maps.
"""

import asyncio
import inspect
import json
import shlex
import struct
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from constants import TransportType
from daharness.models import ToolManifest
from daharness.registry import ToolRegistry

# ── Rich input (prompt_toolkit) — ghost text + context-aware autocomplete ───
# Falls back to plain input() when prompt_toolkit isn't installed. Ghost text
# (grayed inline suggestion) appears for single prefix-match completions; Tab
# opens the full dropdown.  IPython's own Jedi completions are wired in via
# the ``ipython`` command (full Python introspection shell with preloaded
# manifests / registry).
_PROMPT_TOOLKIT = False
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import FileHistory
    _PROMPT_TOOLKIT = True
except ImportError:
    pass


class ToolReplCompleter(Completer if _PROMPT_TOOLKIT else object):
    """Context-aware completer for the tool REPL.

    Completion tiers:
      1. First word  → REPL commands (run, list, info, …)
      2. After a tool-accepting command → discovered tool IDs (from manifests)
      3. After a tool_id in ``run`` → ``--flag`` names from the tool's schema
      4. After ``scope`` → gate subcommands, then their ``--flags``
         (schema mirrors ``_scope_command()`` / ``search_programs``)

    Ghost text (grayed inline suggestion) is shown for single prefix-match
    completions; Tab opens the multi-match dropdown.
    """

    COMMANDS = [
        "list", "run", "info", "resolve", "sweep", "search",
        "safe-args", "sessions", "reindex", "help", "quit", "exit", "ipython", "scope",
    ]
    # Commands whose first argument is a tool_id.
    TOOL_COMMANDS = {"run", "info", "resolve", "safe-args"}

    # ``scope`` subcommand schema — keep in sync with _scope_command().
    # Values double as the tooltip (display_meta) in the completion dropdown.
    SCOPE_SUBCOMMANDS = {
        "on": "arm the gate: on <handle> [--platform P] [--no-strict]",
        "off": "disarm — lab mode, tools unrestricted",
        "status": "armed state, asset counts, manifest_age_s",
        "add-ip": "add-ip <ip> [<hostname>] — bless a resolved in-scope IP",
        "add-host": "add-host <hostname> <ip> — bless a vhost hostname (IP must already be blessed)",
        "rm-host": "rm-host <hostname> — remove a blessed hostname",
        "rm-ip": "rm-ip <ip> — remove a blessed IP",
        "list-ips": "show the operator allowlist",
        "search": "query boards: <kw> [--platform P] [--assets] [--handle H] [--refresh] [--limit N] [--json]",
    }
    # Flags per subcommand (empty dict = no flag completion for it).
    SCOPE_SEARCH_FLAGS = {
        "--platform": "all|h1|intigriti|bugcrowd (default all)",
        "--assets": "load manifests: asset + bounty summary (top 3)",
        "--handle": "exact handle — required for the bugcrowd probe lane",
        "--refresh": "force fresh manifest fetch (with --assets)",
        "--limit": "max matches per lane (default 10)",
        "--json": "print the raw result dict",
    }
    SCOPE_ON_FLAGS = {
        "--platform": "h1|bugcrowd|intigriti (default h1)",
        "--no-strict": "unconfirmed targets warn instead of refuse",
        "--ip-boundary": "hostname/manifest assets must resolve into the blessed IP set (lab drift guard)",
    }

    def __init__(self, manifests: List[ToolManifest]):
        self.manifests = manifests

    def refresh(self, manifests: List[ToolManifest]) -> None:
        self.manifests = manifests

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()
        ends_space = text.endswith(" ")

        # ── Tier 1: command name ──────────────────────────────────────────
        if not parts or (len(parts) == 1 and not ends_space):
            word = parts[0] if parts else ""
            for c in sorted(self.COMMANDS):
                if c.startswith(word):
                    yield Completion(c, start_position=-len(word))
            return

        cmd = parts[0].lower()

        # ── Tier 2: tool_id after a tool-accepting command ─────────────────
        if cmd in self.TOOL_COMMANDS:
            if len(parts) == 1 or (len(parts) == 2 and not ends_space):
                word = parts[1] if len(parts) > 1 else ""
                for m in sorted(self.manifests, key=lambda m: m.module_id):
                    if word.lower() in m.module_id.lower():
                        yield Completion(
                            m.module_id, start_position=-len(word),
                            display_meta=m.transport.value,
                        )
                return

        # ── Tier 2.5: ``scope`` subcommands + their flags ─────────────────
        # The operator-only gate surface gets the same schema-aware
        # completion the tool layer has — subcommand word, then --flags.
        if cmd == "scope":
            if len(parts) == 1 or (len(parts) == 2 and not ends_space):
                word = parts[1] if len(parts) > 1 else ""
                for sub in sorted(self.SCOPE_SUBCOMMANDS):
                    if sub.startswith(word):
                        yield Completion(
                            sub, start_position=-len(word),
                            display_meta=self.SCOPE_SUBCOMMANDS[sub],
                        )
                return
            sub = parts[1].lower()
            current = "" if ends_space else parts[-1]
            flags = (self.SCOPE_SEARCH_FLAGS if sub == "search"
                     else self.SCOPE_ON_FLAGS if sub == "on" else {})
            if flags and current.startswith("--"):
                # Auto-complete flag name as the user types --
                flag_word = current[2:]
                for flag in sorted(flags):
                    if flag[2:].startswith(flag_word):
                        yield Completion(
                            flag, start_position=-len(current),
                            display_meta=flags[flag],
                        )
                return
            if flags and ends_space and complete_event.completion_requested:
                # Tab after a space → show all flags for this subcommand
                for flag in sorted(flags):
                    yield Completion(flag, start_position=0,
                                     display_meta=flags[flag])
                return
            return

        # ── Tier 3: --flag names after a tool_id in ``run`` ────────────────
        if cmd == "run" and len(parts) >= 2:
            tool_id = parts[1]
            manifest = next(
                (m for m in self.manifests if m.module_id == tool_id), None
            )
            if not manifest or not manifest.parameters:
                return
            props = manifest.parameters.get("properties", {})
            current = "" if ends_space else parts[-1]

            if current.startswith("--"):
                # Auto-complete flag name as user types --
                flag_word = current[2:]
                no_mode = flag_word.startswith("no-")
                check = flag_word[3:] if no_mode else flag_word
                for pname in sorted(props):
                    if not check or pname.startswith(check):
                        ptype = props[pname].get("type", "string")
                        pdesc = (props[pname].get("description") or "")[:60]
                        label = f"--no-{pname}" if no_mode else f"--{pname}"
                        yield Completion(
                            label, start_position=-len(current),
                            display_meta=f"{ptype}  {pdesc}",
                        )
            elif ends_space and complete_event.completion_requested:
                # Tab after a space → show all available flags for this tool
                for pname in sorted(props):
                    ptype = props[pname].get("type", "string")
                    pdesc = (props[pname].get("description") or "")[:60]
                    yield Completion(
                        f"--{pname}", start_position=0,
                        display_meta=f"{ptype}  {pdesc}",
                    )


# ── Safe defaults for sweep mode ────────────────────────────────────────────
# These are TEST VALUES, not schema — the schema lives in the manifests.
# Only the runtime values that are harmless (localhost, dry-run) go here.

SAFE_ARGS: Dict[str, Dict[str, Any]] = {
    "auxiliaries.nmap.run_nmap": {"target": "127.0.0.1", "options": "-Pn -p 22"},
    "auxiliaries.smb_scanner.SMBScanner.check_null_session": {"host": "127.0.0.1"},
    "auxiliaries.smb_scanner.run_smb_recon": {"host": "127.0.0.1"},
    "auxiliaries.impacket_suite.atexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.psexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.wmiexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.secretsdump": {"target": "127.0.0.1"},
    "auxiliaries.impacket_suite.smb_enum_shares": {"target": "127.0.0.1"},
    "auxiliaries.impacket_suite.smb_read_file": {"target": "127.0.0.1", "share": "C$", "path": "\\"},
    "listeners.listening.TCPListener.open_listener": {"host": "127.0.0.1", "port": 9999},
    "listeners.listening.TCPListener.close_listener": {"handle": "listener:tcp-9999"},
    "listeners.listening.TCPListener.send_to_brain": {"event": "TEST", "data": "repl sweep test"},
    "listeners.raw_scan.syn_scan": {"target": "127.0.0.1", "ports": "22"},
    "utils.log_reader.read_logs": {"log_type": "brain", "lines": 5},
    "utils.memory_tools.remember_text": {"text": "REPL test memory", "namespace": "test"},
    "utils.memory_tools.recall_text": {"query": "REPL test", "namespace": "test", "limit": 3},
    "utils.paramiko_client.list_sessions": {},
    "utils.paramiko_client.ssh_connect": {"host": "127.0.0.1", "username": "test", "password": "test"},
    "utils.paramiko_client.ssh_exec": {"handle": "ssh:sess-0000", "command": "echo test"},
    "utils.paramiko_client.ssh_shell": {"handle": "ssh:sess-0000", "command": "echo test"},
    "utils.paramiko_client.ssh_close": {"handle": "ssh:sess-0000"},
    "utils.paramiko_client.paramiko_client": {"host": "127.0.0.1", "username": "test", "password": "test", "command": "echo test"},
}

# Tools that require a live service and should be skipped in --safe sweep
REQUIRES_SERVICE = {
    "payloads.metasploiting.MetasploitClient.index_modules",
    "payloads.metasploiting.MetasploitClient.dispatch_metasploit",
    "payloads.metasploiting.MetasploitClient.get_options",
    "payloads.metasploiting.MetasploitClient.interact_session",
    "payloads.metasploiting.MetasploitClient.set_payload",
    "payloads.metasploiting.MetasploitClient.close_msf_session",
    "payloads.searchsploiting.search_exploit",
    "payloads.sqlmap.run_sqlmap",
}


# ── Argument parsing: --flag value, using manifest schema for coercion ──────

def parse_flag_args(tokens: List[str], manifest: Optional[ToolManifest] = None) -> Dict[str, Any]:
    """Parse --flag value style arguments into a dict.

    Uses the tool manifest's parameter schema for type coercion:
      - schema type "integer" / "number"  → int / float
      - schema type "boolean"            → True/False from true/false/yes/no/1/0
      - everything else                   → string

    Bare flags (--flag with no value) are set to True.
    --no-flag sets flag to False.
    Positional args fill required params in declaration order.

    Fallback: if the first token looks like JSON (starts with '{'), the whole
    string is parsed as JSON.  Also supports an explicit --json marker.
    """
    if not tokens:
        return {}

    # Fallback: entire arg string is JSON
    if tokens[0].startswith("{"):
        try:
            return json.loads(" ".join(tokens))
        except json.JSONDecodeError:
            pass

    # --json marker: everything after it is JSON
    if tokens[0] == "--json":
        remainder = tokens[1:]
        if not remainder:
            return {}
        try:
            return json.loads(" ".join(remainder))
        except json.JSONDecodeError as e:
            print(f"  Invalid JSON after --json: {e}")
            return {}

    # Build type map from the manifest schema (the authoritative source)
    type_map: Dict[str, str] = {}
    required_order: List[str] = []
    if manifest and manifest.parameters:
        props = manifest.parameters.get("properties", {})
        for pname, pdef in props.items():
            type_map[pname] = pdef.get("type", "string")
        required_order = list(manifest.parameters.get("required", []))

    args: Dict[str, Any] = {}
    i = 0
    positional_idx = 0

    while i < len(tokens):
        tok = tokens[i]

        # --no-flag → False
        if tok.startswith("--no-"):
            flag_name = tok[5:]
            args[flag_name] = False
            i += 1
            continue

        # --flag value or --flag (bare → True)
        if tok.startswith("--"):
            flag_name = tok[2:]
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                raw_value = tokens[i + 1]
                args[flag_name] = _coerce_value(raw_value, type_map.get(flag_name, "string"))
                i += 2
            else:
                args[flag_name] = True
                i += 1
            continue

        # Positional: assign to the next unfilled required param
        if positional_idx < len(required_order):
            pname = required_order[positional_idx]
            # Only fill if not already set by a --flag
            if pname not in args:
                args[pname] = _coerce_value(tok, type_map.get(pname, "string"))
                positional_idx += 1
                i += 1
                continue

        print(f"  Warning: skipping unrecognized arg: {tok}")
        i += 1

    return args


def _coerce_value(raw: str, schema_type: str) -> Any:
    """Coerce a raw string value using the schema-declared type."""
    if schema_type in ("integer", "int"):
        try:
            return int(raw)
        except ValueError:
            return raw
    elif schema_type in ("number", "float"):
        try:
            return float(raw)
        except ValueError:
            return raw
    elif schema_type in ("boolean", "bool"):
        return raw.lower() in ("true", "yes", "1", "on")
    return raw


# ── Lightweight executor (no ChromaDB, no secretary) ─────────────────────────

def _make_executor() -> ToolRegistry:
    """Create a bare ToolRegistry instance for tool execution without ChromaDB."""
    reg = ToolRegistry.__new__(ToolRegistry)
    reg._tool_instances = {}
    return reg


# ── Discover tools ──────────────────────────────────────────────────────────

def discover_tools() -> List[ToolManifest]:
    """Discover all tools using the registry's static+dynamic scan (no ChromaDB)."""
    reg = ToolRegistry.__new__(ToolRegistry)
    return reg.discover_local_tools()


# ── Run a tool ───────────────────────────────────────────────────────────────

async def run_tool(tool_id: str, arguments: Dict[str, Any], manifests: List[ToolManifest]) -> Dict[str, Any]:
    """Run a single tool by ID and return the result dict."""
    manifest = next((m for m in manifests if m.module_id == tool_id), None)
    if manifest is None:
        return {"error": f"Unknown tool_id: {tool_id}", "status": "Failed"}

    executor = _make_executor()

    print(f"  [repl] Running {tool_id}")
    print(f"  [repl] Transport: {manifest.transport.value}")
    print(f"  [repl] Args: {json.dumps(arguments, default=str)[:500]}")
    print(f"  [repl] Implementation: {manifest.implementation_path}")

    start = time.monotonic()
    try:
        result = await executor.execute_tool(manifest, arguments)
    except Exception as exc:
        result = {"error": f"Exception during execution: {exc}", "status": "Failed"}
        traceback.print_exc()
    elapsed = time.monotonic() - start

    result["_elapsed_s"] = round(elapsed, 2)
    return result


# ── Resolve and inspect a tool function ──────────────────────────────────────

def resolve_callable(tool_id: str):
    """Resolve a tool_id to its Python callable (without running it)."""
    executor = _make_executor()
    return executor._resolve_callable(tool_id)


# ── REPL ─────────────────────────────────────────────────────────────────────

def print_manifest(m: ToolManifest, verbose: bool = False):
    """Print a tool manifest summary."""
    handle_info = ""
    if m.accepted_handle_kinds:
        handle_info = f"  handles={list(m.accepted_handle_kinds)}"
    print(f"  {m.module_id}")
    print(f"    transport:  {m.transport.value}")
    print(f"    capability: {m.internal_semantic_capability[:120]}")
    print(f"    path:        {m.implementation_path}")
    if handle_info:
        print(f"    {handle_info}")
    if verbose and m.parameters:
        props = m.parameters.get("properties", {})
        req = m.parameters.get("required", [])
        for pname, pdef in props.items():
            req_mark = "*" if pname in req else " "
            ptype = pdef.get("type", "?")
            pdesc = pdef.get("description", "")
            print(f"      {req_mark} {pname}: {ptype}  {pdesc}")


def print_result(result: Dict[str, Any]):
    """Pretty-print a tool execution result."""
    status = result.get("status", "unknown")
    elapsed = result.get("_elapsed_s", "?")
    marker = "✓" if status == "Success" else "✗"
    print(f"  [{marker}] Status: {status}  ({elapsed}s)")
    if result.get("degraded"):
        print("  ⚠ degraded: Brain socket down — executed IN-PROCESS in this REPL.")
        print("    Any session opened by this call is REPL-local (the agent cannot see it).")

    stdout = result.get("stdout", "")
    if stdout:
        display = stdout[:2000] if len(stdout) > 2000 else stdout
        if len(stdout) > 2000:
            display += f"\n  ... ({len(stdout) - 2000} more chars)"
        print(f"  stdout:\n{display}")

    res = result.get("result")
    if res is not None:
        display = json.dumps(res, default=str, indent=2)[:2000]
        print(f"  result:\n{display}")

    error = result.get("error")
    if error:
        print(f"  error: {error}")

    stderr = result.get("stderr", "")
    if stderr:
        display = stderr[:1000] if len(stderr) > 1000 else stderr
        print(f"  stderr:\n{display}")


# ── Shared sessions (REPL ↔ Brain) ────────────────────────────────────
# utils/session_manager.SessionManager is a PROCESS-LOCAL singleton: whichever
# process actually executes ssh_connect / open_listener holds the live object.
# The Brain sidecar (/tmp/brain.sock) is the shared owner — the agent's Bridge
# dispatches through that same socket — so a session opened ON the Brain is
# usable by BOTH lanes. msf: handles are daemon-backed (msfrpcd) and were
# always cross-process visible. The `sessions` command shows both worlds side
# by side so you always know which process holds what.

BRAIN_SOCKET = "/tmp/brain.sock"
_BRAIN_TIMEOUT = 60.0


def _brain_pack(payload: bytes) -> bytes:
    """4-byte big-endian length framing, byte-identical to
    listeners.thebrain.pack_message — reimplemented locally so the REPL never
    imports the Brain module (its module-level ctypes CDLL load of frameit.so
    is a side effect a diagnostic tool must not carry)."""
    return struct.pack("!I", len(payload)) + payload


async def _brain_read_message(reader) -> bytes:
    """Read one length-prefixed reply (same framing as the Brain side)."""
    header = await reader.readexactly(4)
    (length,) = struct.unpack("!I", header)
    if length > 10 * 1024 * 1024:
        raise ValueError(f"declared message length {length} exceeds max {10 * 1024 * 1024}")
    return await reader.readexactly(length)


async def _brain_call(tool_id: str, arguments: Dict[str, Any], brain_session: int = 0) -> Dict[str, Any]:
    """Route one tool call to the Brain sidecar (CALL_TOOL wire format), with
    NO in-process fallback: a fallback would strand session state in this REPL
    process, invisible to the agent — the split-brain this helper exists to
    prevent."""
    message = f"CALL_TOOL|{brain_session}|{tool_id}|{json.dumps(arguments)}"
    start = time.monotonic()

    try:
        reader, writer = await asyncio.open_unix_connection(BRAIN_SOCKET)
    except (FileNotFoundError, ConnectionError, OSError) as e:
        return {
            "stdout": "",
            "status": "Failed",
            "error": (
                f"Brain sidecar is down ({BRAIN_SOCKET}: {e}). Refusing to run "
                f"{tool_id} in-process — the session would be REPL-local and "
                "invisible to the agent. Start the Brain, or use `run` for an "
                "explicitly REPL-local (unshared) session."
            ),
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    try:
        writer.write(_brain_pack(message.encode()))
        await writer.drain()
        data = await asyncio.wait_for(_brain_read_message(reader), timeout=_BRAIN_TIMEOUT)
        writer.close()
        await writer.wait_closed()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError) as e:
        try:
            writer.close()
        except Exception:
            pass
        return {
            "stdout": "",
            "status": "Failed",
            "error": (
                f"Brain call {tool_id} did not complete within {_BRAIN_TIMEOUT:.0f}s "
                f"({type(e).__name__}); it may still be running on the Brain."
            ),
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    text = data.decode(errors="replace")
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Legacy raw-text Brain — surface the raw text honestly.
        return {
            "stdout": text,
            "status": "Success",
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    status = str(envelope.get("status", "")).lower()
    error_msg = envelope.get("error")
    result_value = envelope.get("result")
    stdout = result_value if result_value is not None else (error_msg or "")
    if not isinstance(stdout, str):
        stdout = json.dumps(stdout, default=str)
    shaped: Dict[str, Any] = {
        "stdout": stdout,
        "status": "Success" if status == "success" else "Failed",
        "_elapsed_s": round(time.monotonic() - start, 2),
    }
    if status != "success" and error_msg:
        shaped["error"] = error_msg
    return shaped


async def _sessions_command(manifests: List[ToolManifest]):
    """List sessions from BOTH lanes so the operator always knows what is shared."""
    print("  ── Brain-held sessions (SHARED with agent — these handles work on both sides) ──")
    result = await _brain_call("utils.paramiko_client.list_sessions", {})
    print_result(result)

    print("  ── REPL-local sessions (THIS process only — agent cannot see these) ──")
    executor = _make_executor()
    func, err = executor._resolve_callable("utils.paramiko_client.list_sessions")
    if func is None:
        print(f"  ✗ Resolve failed: {err}")
        return
    try:
        output = await asyncio.to_thread(func)
        print(output)
    except Exception as exc:
        print(f"  ✗ Local list failed: {exc}")

    print("  [i] msf: handles are backed by the shared msfrpcd daemon and are")
    print("      visible from both lanes regardless of which side opened them.")


def repl_help():
    print("""
Tool REPL commands:
  list [filter]          List all tools (optional substring filter)
  search <query>         Semantic search via ChromaDB (needs Ollama + ChromaDB);
                         results render worst-first so rank #1 sits right above the prompt
  info <tool_id>         Show full manifest for a tool
  resolve <tool_id>      Resolve a tool_id to its Python callable (dry run)
  sessions               Show Brain-held (SHARED with agent) vs REPL-local sessions
  run <tool_id> [--flag value ...]   Run a tool with flag args (schema-aware)
  run <tool_id> --json '{...}'       Run a tool with JSON args
  run <tool_id>          Run with safe-default args (if defined)
  sweep [--safe|--force] Run all tools with safe defaults
  safe-args [tool_id]    Show safe-sweep args for a tool (or all)
  reindex                Re-discover tools
  ipython                Drop into IPython with tools preloaded (Jedi completions)
  scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]
                         Arm the packet-scope gate (send_packet refuses
                         out-of-scope destinations; operator-only, not exposed
                         to the agent). 'scope off' disarms (lab mode).
  scope status|off|add-ip <ip> [<hostname>]|rm-ip <ip>|list-ips|search <kw> [--assets]
  help                   This message
  quit / exit            Leave the REPL

Flag args are type-coerced from the tool's own manifest schema:
  --target 10.0.0.1       string (default)
  --port 22               integer (per schema)
  --verbose               bare flag → True
  --no-verbose             → False
  --limit 5                integer (per schema)

Positional args fill required params in order:
  run auxiliaries.nmap.run_nmap 10.0.0.1 "-Pn -p 22"
  (equivalent to --target 10.0.0.1 --options "-Pn -p 22")
""")


def _find_manifest(tool_id: str, manifests: List[ToolManifest]) -> Optional[ToolManifest]:
    """Find a manifest by exact ID, or by substring match (unique only)."""
    m = next((m for m in manifests if m.module_id == tool_id), None)
    if m is not None:
        return m
    matches = [m for m in manifests if tool_id in m.module_id]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"  Multiple matches for '{tool_id}':")
        for mm in matches:
            print(f"    {mm.module_id}")
    return None


def _scope_command(rest: str):
    """Handle the ``scope`` REPL command — operator-only packet-scope gate.

    This is the ONLY control surface for the packet-scope gate; it is
    deliberately not exposed as an ``@framework_tool``, so the secretary
    agent cannot arm/disarm or bless IPs.  When armed, ``send_packet``
    refuses sends to destinations not confirmed in-scope (see
    :mod:`utils.scope_gate`).
    """
    from utils import scope_gate

    try:
        parts = shlex.split(rest)
    except ValueError as e:
        print(f"  Argument parse error: {e}")
        return
    if not parts:
        print("  Packet-scope gate (operator-only — not exposed to the agent).")
        print("  When armed, send_packet refuses packets to destinations not")
        print("  confirmed in-scope for the loaded program. Disarmed = lab mode.")
        print("  Commands:")
        print("    scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]")
        print("    scope off")
        print("    scope status")
        print("    scope search <kw> [--assets]  (query the boards: matching programs + bounty-relevant stats)")
        print("    scope add-ip <ip> [<hostname>]   (bless a resolved in-scope IP)")
        print("    scope add-host <hostname> <ip>   (bless a vhost hostname; IP must already be blessed)")
        print("    scope rm-host <hostname>")
        print("    scope rm-ip <ip>")
        print("    scope list-ips")
        st = scope_gate.status()
        if st.get("armed"):
            print(f"  Current: ARMED — {st.get('handle')}/{st.get('platform')} "
                  f"strict={st.get('strict')} allowlist={st.get('allowlist_size',0)}")
        else:
            print("  Current: disarmed (lab mode — sends unrestricted)")
        return

    sub = parts[0].lower()

    if sub == "on":
        if len(parts) < 2:
            print("  Usage: scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]")
            return
        handle = parts[1]
        platform = "h1"
        strict = True
        ip_boundary = False
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok == "--no-strict":
                strict = False
                i += 1
            elif tok == "--ip-boundary":
                ip_boundary = True
                i += 1
            elif tok == "--platform" and i + 1 < len(parts) and not parts[i + 1].startswith("--"):
                platform = parts[i + 1]
                i += 2
            elif tok.startswith("--platform="):
                platform = tok.split("=", 1)[1]
                i += 1
            else:
                print(f"  Ignoring unknown flag: {tok}")
                i += 1
        res = scope_gate.arm(handle, platform, strict, ip_boundary=ip_boundary)

    elif sub == "off":
        res = scope_gate.disarm()

    elif sub == "status":
        res = scope_gate.status()

    elif sub == "search":
        # Board-wide program search (discovery): keyword over the H1/Intigriti
        # program indexes, exact-handle probe for Bugcrowd.  NOT a search of
        # the armed manifest — that's what check_scope is for.
        query = ""
        handle = ""
        platform = "all"
        limit = 10
        with_assets = False
        refresh = False
        as_json = False
        # Positional-tolerant parse: the keyword may come before or after the
        # flags (Tab-complete inserts --flags mid-line), extra positional
        # tokens join the keyword (multi-word program names).
        tokens = parts[1:]
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--assets":
                with_assets = True
            elif tok == "--refresh":
                refresh = True
            elif tok == "--json":
                as_json = True
            elif tok.startswith("--limit="):
                limit = int(tok.split("=", 1)[1])
            elif tok == "--limit" and i + 1 < len(tokens):
                i += 1
                limit = int(tokens[i])
            elif tok.startswith("--handle="):
                handle = tok.split("=", 1)[1]
            elif tok == "--handle" and i + 1 < len(tokens):
                i += 1
                handle = tokens[i]
            elif tok.startswith("--platform="):
                platform = tok.split("=", 1)[1]
            elif tok == "--platform" and i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                i += 1
                platform = tokens[i]
            elif tok.startswith("--"):
                print(f"  Ignoring unknown flag: {tok}")
            elif not query:
                query = tok
            else:
                query = f"{query} {tok}"  # multi-word keyword
            i += 1
        if not query and not handle:
            print("  Usage: scope search <query> [--platform all|h1|intigriti|bugcrowd] [--assets]")
            print("                            [--handle <h>] [--refresh] [--limit N] [--json]")
            return
        from auxiliaries import program_scope
        res = program_scope.search_programs(query=query, platform=platform, limit=limit,
                                            with_assets=with_assets, handle=handle,
                                            refresh=refresh)
        if as_json:
            print("  " + json.dumps(res, indent=2, default=str))
            return
        if not res.get("rows"):
            err = res.get("error") or res.get("lane_errors") or "no match"
            print("  scope search: " + (err if isinstance(err, str) else json.dumps(err)))
            return
        for r in res["rows"]:
            bounty = r.get("bounty")
            btxt = (("bounties=yes" if bounty else "bounties=no")
                    if isinstance(bounty, bool) else str(bounty or ""))
            state = f" state={r['state']}" if r.get("state") else ""
            name = r.get("name") or "?"
            print(f"  {r['platform']:<9} | {str(r.get('handle') or '?'):<24} | {name} | {btxt}{state}")
        for lane, err in (res.get("lane_errors") or {}).items():
            print(f"  [{lane}] {err}")
        if res.get("lane_truncated"):
            print("  (index truncated at the page cap — refine the query)")
        for key, a in (res.get("assets") or {}).items():
            if not isinstance(a, dict) or a.get("error"):
                print(f"  == {key}: {a.get('error') if isinstance(a, dict) else a}")
                continue
            counts = a.get("counts") or {}
            bs = a.get("bounty_stats") or {}
            print(f"  == {key} — {a.get('program_name') or ''}: "
                  f"{counts.get('in_scope', 0)} in-scope, "
                  f"{counts.get('out_of_scope_assets', 0)} OOS, "
                  f"bounty-eligible {bs.get('bounty_eligible_in_scope', 0)} / "
                  f"no-bounty {bs.get('no_bounty_in_scope', 0)}")
            for row in a.get("assets") or []:
                flag = "bounty" if row.get("eligible_for_bounty") else "no-bounty"
                print(f"     {str(row.get('asset_type') or '?'):<9} "
                      f"{str(row.get('asset_identifier') or ''):<44} {flag:<9} "
                      f"{row.get('detail') or ''}")
            if a.get("assets_truncated"):
                print("     ... (asset rows truncated)")
        return

    elif sub in ("add-ip", "add_ip", "add"):
        if len(parts) < 2:
            print("  Usage: scope add-ip <ip> [<hostname>]")
            return
        ip = parts[1]
        hostname = parts[2] if len(parts) > 2 else ""
        res = scope_gate.add_ip(ip, hostname)

    elif sub in ("add-host", "add_host"):
        if len(parts) < 3:
            print("  Usage: scope add-host <hostname> <ip>")
            return
        res = scope_gate.add_host(parts[1], parts[2])

    elif sub in ("rm-host", "rm_host"):
        if len(parts) < 2:
            print("  Usage: scope rm-host <hostname>")
            return
        res = scope_gate.remove_host(parts[1])

    elif sub in ("rm-ip", "rm_ip", "remove", "rm"):
        if len(parts) < 2:
            print("  Usage: scope rm-ip <ip>")
            return
        res = scope_gate.remove_ip(parts[1])

    elif sub in ("list-ips", "list_ips", "list", "ips"):
        res = scope_gate.list_ips()

    else:
        print(f"  Unknown scope subcommand: {sub!r}. Try 'scope' for help.")
        return

    print("  " + json.dumps(res, indent=2, default=str))


async def repl_loop(manifests: List[ToolManifest]):
    """Interactive REPL loop."""
    repl_help()

    # Rich input: ghost text + context-aware autocomplete via prompt_toolkit.
    # Falls back to plain input() when the library isn't available.
    session = None
    completer = None
    if _PROMPT_TOOLKIT:
        completer = ToolReplCompleter(manifests)
        session = PromptSession(
            completer=completer,
            complete_while_typing=True,
            history=FileHistory(str(Path.home() / ".tool_repl_history")),
        )

    async def _read_line() -> str:
        # Scope-armed indicator: a checkmark when a scope is armed (sends
        # gated), no sign when disarmed (lab mode). Recomputed each prompt
        # so 'scope on/off' is reflected immediately. Cheap: one stat/json.
        try:
            from utils.scope_gate import is_armed
            _mark = "✓ " if is_armed() else ""
        except Exception:
            _mark = ""
        _prompt = f"\n{_mark}repl> "
        if session is not None:
            return await session.prompt_async(_prompt)
        return input(_prompt)

    while True:
        try:
            line = (await _read_line()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help" or cmd == "h":
            repl_help()

        elif cmd == "list":
            filter_str = rest.lower()
            shown = 0
            for m in manifests:
                if filter_str and filter_str not in m.module_id.lower():
                    continue
                print_manifest(m)
                shown += 1
            print(f"\n  {shown} tool(s) shown ({len(manifests)} total)")

        elif cmd == "info":
            if not rest:
                print("  Usage: info <tool_id>")
                continue
            m = _find_manifest(rest, manifests)
            if m is None:
                if not any(rest in mm.module_id for mm in manifests):
                    print(f"  No tool found matching '{rest}'")
                continue
            print_manifest(m, verbose=True)

        elif cmd == "resolve":
            if not rest:
                print("  Usage: resolve <tool_id>")
                continue
            func, err = resolve_callable(rest)
            if func is None:
                print(f"  ✗ Resolve failed: {err}")
            else:
                print(f"  ✓ Resolved to: {func}")
                sig = inspect.signature(func)
                print(f"    Signature: {func.__qualname__}{sig}")
                doc = getattr(func, "_tool_doc", None) or inspect.getdoc(func) or ""
                if doc:
                    print(f"    Doc: {doc[:200]}")

        elif cmd == "run":
            if not rest:
                print("  Usage: run <tool_id> [--flag value ...] or run <tool_id> --json '{...}'")
                continue
            # Use shlex.split so shell-style quoting is honoured: without it,
            # --target 'https://example.com' passes the literal quotes as
            # part of the value → ZAP gets url='https://example.com' → 400.
            try:
                tokens = shlex.split(rest)
            except ValueError as e:
                print(f"  Argument parse error (unbalanced quotes?): {e}")
                continue
            tool_id = tokens[0]
            arg_tokens = tokens[1:]

            m = _find_manifest(tool_id, manifests)
            if m is None:
                if not any(tool_id in mm.module_id for mm in manifests):
                    print(f"  Unknown tool: {tool_id}")
                continue

            if not arg_tokens:
                arguments = dict(SAFE_ARGS.get(tool_id, {}))
                if not arguments and m.parameters.get("required"):
                    req = m.parameters["required"]
                    print(f"  No safe defaults for {tool_id}. Required params: {req}")
                    print(f"  Usage: run {tool_id} --{' --'.join(req)} <value> ...")
                elif not arguments:
                    print(f"  No safe defaults for {tool_id}. Running with no args.")
            else:
                arguments = parse_flag_args(arg_tokens, manifest=m)

            result = await run_tool(tool_id, arguments, manifests)
            print_result(result)

        elif cmd == "sweep":
            force = "--force" in rest or "-f" in rest
            safe = not force

            print(f"  Sweeping {len(manifests)} tools (safe={safe})...")
            results = {}
            for m in manifests:
                tid = m.module_id
                if safe and tid in REQUIRES_SERVICE:
                    print(f"\n  ⏭  {tid} — requires live service, skipping (use --force to include)")
                    results[tid] = {"status": "Skipped", "reason": "requires live service"}
                    continue

                args = SAFE_ARGS.get(tid, {})
                print(f"\n  ── {tid} ──")
                result = await run_tool(tid, args, manifests)
                print_result(result)
                results[tid] = result

            success = sum(1 for r in results.values() if r.get("status") == "Success")
            failed = sum(1 for r in results.values() if r.get("status") == "Failed")
            skipped = sum(1 for r in results.values() if r.get("status") == "Skipped")
            errors = sum(1 for r in results.values() if "error" in r and r.get("status") not in ("Skipped",))
            print(f"\n  ══ Sweep Summary ══")
            print(f"  Total: {len(results)}  ✓ Success: {success}  ✗ Failed: {failed}  ⏭ Skipped: {skipped}  ⚠ Errors: {errors}")
            for tid, r in results.items():
                marker = {"Success": "✓", "Failed": "✗", "Skipped": "⏭"}.get(r.get("status", ""), "⚠")
                elapsed = r.get("_elapsed_s", "?")
                err = r.get("error", "")[:80] if r.get("error") else ""
                print(f"    {marker} {tid:50s} {r.get('status', '?'):8s} {elapsed}s {err}")

        elif cmd == "safe-args":
            if not rest:
                print("  Tools with safe args defined:")
                for tid, args in sorted(SAFE_ARGS.items()):
                    print(f"    {tid}: {json.dumps(args)}")
                continue
            args = SAFE_ARGS.get(rest)
            if args is not None:
                print(f"  {rest}: {json.dumps(args, indent=2)}")
            else:
                print(f"  No safe args defined for '{rest}'. It will be run with empty args {{}}.")

        elif cmd == "search":
            if not rest:
                print("  Usage: search <semantic query>")
                continue
            try:
                from daharness.registry import OllamaEmbeddingFunction, ToolRegistry as RealRegistry
                real_reg = RealRegistry(embedding_model=OllamaEmbeddingFunction())
                results = await real_reg.find_tools(rest)
                if not results:
                    print("  No results.")
                # find_tools returns best-first (T-002: array position == rank,
                # and the secretary/agents read array position — do NOT change
                # that ordering).  The terminal renders top-down, so the REPL
                # prints the list in reverse: worst match lands highest on
                # screen, rank #1 prints LAST, right above the prompt instead
                # of scrolling off into scrollback.
                for rank, m in reversed(list(enumerate(results, 1))):
                    dist = f"  dist={m.distance}" if m.distance is not None else ""
                    print_manifest(m, verbose=True)
                    print(f"    #{rank}{dist}")
            except Exception as e:
                print(f"  Search failed (needs ChromaDB + Ollama): {e}")

        elif cmd == "reindex":
            manifests = discover_tools()
            if completer is not None:
                completer.refresh(manifests)
            print(f"  Re-discovered {len(manifests)} tools.")

        elif cmd == "ipython":
            try:
                from IPython import embed

                async def quick_run(tool_id: str, **kwargs):
                    """Convenience wrapper: await quick_run("aux.nmap.run_nmap", target="127.0.0.1")"""
                    return await run_tool(tool_id, kwargs, manifests)

                user_ns = {
                    "manifests": manifests,
                    "registry": _make_executor(),
                    "run_tool": run_tool,
                    "quick_run": quick_run,
                    "discover_tools": discover_tools,
                    "resolve_callable": resolve_callable,
                    "ToolManifest": ToolManifest,
                    "ToolRegistry": ToolRegistry,
                }
                print("  Dropping into IPython (Jedi completions + rich display).")
                print("  Available: manifests, registry, run_tool, quick_run,")
                print("             discover_tools, resolve_callable, ToolManifest, ToolRegistry")
                print("  quick_run:  await quick_run(id, target=x, port=y)")
                print("  run_tool:   await run_tool(id, args_dict, manifests)")
                print("  Ctrl+D / exit() to return.\n")

                # IPython.embed() → prompt_toolkit → asyncio.run() crashes with
                # "cannot be called from a running event loop" when we're inside
                # asyncio.run(repl_loop(...)).  Run embed() in a separate thread
                # so it gets a clean event-loop context.  asyncio.to_thread()
                # blocks this coroutine until the user exits IPython.
                def _embed():
                    embed(user_ns=user_ns, header="")

                await asyncio.to_thread(_embed)
            except ImportError:
                print("  IPython not installed. Install with: pip install ipython")

        elif cmd == "sessions":
            await _sessions_command(manifests)

        elif cmd == "scope":
            _scope_command(rest)

        else:
            print(f"  Unknown command: {cmd}. Type 'help' for commands.")


# ── One-shot run ─────────────────────────────────────────────────────────────

async def oneshot_run(tool_id: str, arg_tokens: List[str]):
    """Run a single tool and print the result, then exit."""
    manifests = discover_tools()
    m = _find_manifest(tool_id, manifests)
    if m is None:
        print(f"Unknown tool: {tool_id}")
        return 1

    if not arg_tokens:
        arguments = dict(SAFE_ARGS.get(tool_id, {}))
        if not arguments and m.parameters.get("required"):
            req = m.parameters["required"]
            print(f"No safe defaults for {tool_id}. Required: {req}")
            print(f"Usage: python tool_repl.py run {tool_id} --{' --'.join(req)} <value> ...")
    else:
        arguments = parse_flag_args(arg_tokens, manifest=m)

    result = await run_tool(tool_id, arguments, manifests)
    print_result(result)
    return 0 if result.get("status") == "Success" else 1


async def oneshot_info(tool_id: str):
    """Show info for a single tool, then exit."""
    manifests = discover_tools()
    m = _find_manifest(tool_id, manifests)
    if m is None:
        print(f"No tool found matching '{tool_id}'")
        return 1
    print_manifest(m, verbose=True)

    func, err = resolve_callable(tool_id)
    if func:
        print(f"  Resolved: {func}")
    else:
        print(f"  Resolve: FAILED — {err}")
    return 0


async def oneshot_sweep(safe: bool = True):
    """Sweep all tools and print results."""
    manifests = discover_tools()
    print(f"Discovered {len(manifests)} tools. Sweeping (safe={safe})...")
    results = {}
    for m in manifests:
        tid = m.module_id
        if safe and tid in REQUIRES_SERVICE:
            print(f"\n  ⏭  {tid} — requires live service, skipping (use --force to include)")
            results[tid] = {"status": "Skipped", "reason": "requires live service"}
            continue

        args = SAFE_ARGS.get(tid, {})
        print(f"\n  ── {tid} ──")
        result = await run_tool(tid, args, manifests)
        print_result(result)
        results[tid] = result

    success = sum(1 for r in results.values() if r.get("status") == "Success")
    failed = sum(1 for r in results.values() if r.get("status") == "Failed")
    skipped = sum(1 for r in results.values() if r.get("status") == "Skipped")
    errors = sum(1 for r in results.values() if "error" in r and r.get("status") not in ("Skipped",))
    print(f"\n  ══ Sweep Summary ══")
    print(f"  Total: {len(results)}  ✓ Success: {success}  ✗ Failed: {failed}  ⏭ Skipped: {skipped}  ⚠ Errors: {errors}")
    for tid, r in results.items():
        marker = {"Success": "✓", "Failed": "✗", "Skipped": "⏭"}.get(r.get("status", ""), "⚠")
        elapsed = r.get("_elapsed_s", "?")
        err = r.get("error", "")[:80] if r.get("error") else ""
        print(f"    {marker} {tid:50s} {r.get('status', '?'):8s} {elapsed}s {err}")

    return 1 if failed > 0 else 0


# ── CLI ──────────────────────────────────────────────────────────────────────
# We DO NOT use argparse for the `run` subcommand because tool flags like
# --target, --port etc would collide with argparse's own flags.  Instead we
# just look at sys.argv directly and dispatch manually.

def main():
    args = sys.argv[1:]
    if not args:
        # Interactive REPL
        print("Discovering tools...")
        manifests = discover_tools()
        print(f"Found {len(manifests)} tools. Type 'help' for commands.\n")
        asyncio.run(repl_loop(manifests))
        return

    mode = args[0]

    if mode == "run":
        if len(args) < 2:
            print("Usage: python tool_repl.py run <tool_id> [--flag value ...]")
            print("       python tool_repl.py run <tool_id> --json '{...}'")
            print("       python tool_repl.py run <tool_id>   (uses safe defaults)")
            sys.exit(1)
        tool_id = args[1]
        arg_tokens = args[2:]
        sys.exit(asyncio.run(oneshot_run(tool_id, arg_tokens)))

    elif mode == "info":
        if len(args) < 2:
            print("Usage: python tool_repl.py info <tool_id>")
            sys.exit(1)
        sys.exit(asyncio.run(oneshot_info(args[1])))

    elif mode == "sweep":
        force = "--force" in args or "-f" in args
        safe = not force
        sys.exit(asyncio.run(oneshot_sweep(safe=safe)))

    elif mode == "search":
        if len(args) < 2:
            print("Usage: python tool_repl.py search <query>")
            sys.exit(1)
        query = " ".join(args[1:])

        async def _search():
            from daharness.registry import OllamaEmbeddingFunction, ToolRegistry as RealRegistry
            real_reg = RealRegistry(embedding_model=OllamaEmbeddingFunction())
            results = await real_reg.find_tools(query)
            if not results:
                print("No results.")
            for m in results:
                dist = f"  dist={m.distance}" if m.distance is not None else ""
                print_manifest(m, verbose=True)
                print(f"    {dist}")

        asyncio.run(_search())

    else:
        print(f"Unknown mode: {mode}")
        print("Modes: run, info, sweep, search")
        print("Or run without arguments for the interactive REPL.")
        sys.exit(1)


if __name__ == "__main__":
    main()
