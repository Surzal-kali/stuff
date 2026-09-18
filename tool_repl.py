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
  sweep [--safe]              — run every discoverable tool with safe/no-op args
  info <id>                   — show a tool's manifest without running it
  search <query>              — semantic search (needs ChromaDB + Ollama)

Argument parsing uses the tool's own parameter schema (from the manifest
discovered at startup) for type coercion — no hardcoded type maps.
"""

import asyncio
import inspect
import json
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

    Ghost text (grayed inline suggestion) is shown for single prefix-match
    completions; Tab opens the multi-match dropdown.
    """

    COMMANDS = [
        "list", "run", "info", "resolve", "sweep", "search",
        "safe-args", "reindex", "help", "quit", "exit", "ipython",
    ]
    # Commands whose first argument is a tool_id.
    TOOL_COMMANDS = {"run", "info", "resolve", "safe-args"}

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


def repl_help():
    print("""
Tool REPL commands:
  list [filter]          List all tools (optional substring filter)
  search <query>         Semantic search via ChromaDB (needs Ollama + ChromaDB)
  info <tool_id>         Show full manifest for a tool
  resolve <tool_id>      Resolve a tool_id to its Python callable (dry run)
  run <tool_id> [--flag value ...]   Run a tool with flag args (schema-aware)
  run <tool_id> --json '{...}'       Run a tool with JSON args
  run <tool_id>          Run with safe-default args (if defined)
  sweep [--safe|--force] Run all tools with safe defaults
  safe-args [tool_id]    Show safe-sweep args for a tool (or all)
  reindex                Re-discover tools
  ipython                Drop into IPython with tools preloaded (Jedi completions)
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
        if session is not None:
            return await session.prompt_async("\nrepl> ")
        return input("\nrepl> ")

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
            tokens = rest.split()
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
                for m in results:
                    dist = f"  dist={m.distance}" if m.distance is not None else ""
                    print_manifest(m, verbose=True)
                    print(f"    {dist}")
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
