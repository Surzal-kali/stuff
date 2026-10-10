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
import os
import shlex
import struct
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Load .env (same as bootstrap.py) so OLLAMA_COMPLETION_MODEL and other
# env-tunable knobs are visible. tool_repl.py is a standalone entry point —
# without this, os.getenv() only sees the system environment, not .env.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

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
    "auxiliaries.ldap_search.ldap_rootdse": {"host": "127.0.0.1"},
    "auxiliaries.ldap_search.ldap_search": {"host": "127.0.0.1", "base_dn": "dc=example,dc=com"},
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


# ── IPython kitted namespace: aliases + signature-bearing wrappers ──────────
#
# The plain ``ipython`` command used to inject a flat ``List[ToolManifest]``
# and a single ``quick_run("dotted.tool.id", **kw)`` helper.  Jedi completions
# never fired because tool ids are *quoted strings*, not Python symbols — the
# completer has nothing to index.  This section builds, per discovered tool,
# an ``async def`` wrapper that:
#
#   • lives in the IPython namespace under a short, ergonomic alias
#   • carries an ``inspect.Signature`` built from the manifest's JSON-schema
#     parameters so IPython shows ``target*``, ``options``, ``port`` with
#     type + description tooltips on ``(<Tab>``
#   • has a ``__doc__`` assembled from the manifest's semantic capability +
#     per-parameter descriptions so ``tool?`` / ``tool??`` work
#   • dispatches through ``run_tool`` (→ executor → transport dispatch →
#     scope gate + preflight) — never through raw ``resolve_callable`` — so
#     the safety invariants that the REPL's ``run`` command enforces are
#     identical inside IPython.
#
# The wrappers are plain ``async def`` closures; IPython's ``%autoawait
# asyncio`` (the default) lets the operator write ``await nmap(target=...)``
# at the top level, same as the old ``quick_run``.

# Curated short aliases for the most-used tools.  Keyed by the full
# ``module_id`` (so a rename in the source tree breaks loudly here, not
# silently at the keyboard).  Tools not in this map fall through to
# auto-derivation below.
_TOOL_ALIASES: Dict[str, str] = {
    # auxiliaries/
    "auxiliaries.nmap.run_nmap": "nmap",
    "auxiliaries.masscan.run_masscan": "masscan",
    "auxiliaries.ffuf_tools.run_ffuf": "ffuf",
    "auxiliaries.smb_scanner.check_null_session": "smb_null",
    "auxiliaries.smb_scanner.run_smb_recon": "smb_recon",
    "auxiliaries.ftp_recon.run_ftp_recon": "ftp_recon",
    "auxiliaries.dns_lookup.run_dns_lookup": "dns_lookup",
    "auxiliaries.tls_info.run_tls_info": "tls_info",
    "auxiliaries.cors_probe.run_cors_probe": "cors_probe",
    "auxiliaries.ssrf_probe.run_ssrf_probe": "ssrf_probe",
    "auxiliaries.web_probe.run_web_probe": "web_probe",
    "auxiliaries.web_login_brute.run_web_login_brute": "web_brute",
    "auxiliaries.ldap_search.ldap_rootdse": "ldap_rootdse",
    "auxiliaries.ldap_search.ldap_search": "ldap_search",
    "auxiliaries.ssh_exec.run_ssh_exec": "ssh_exec",
    "auxiliaries.impacket_suite.secretsdump": "secretsdump",
    "auxiliaries.impacket_suite.psexec_exec": "psexec",
    "auxiliaries.impacket_suite.wmiexec_exec": "wmiexec",
    "auxiliaries.impacket_suite.atexec_exec": "atexec",
    "auxiliaries.impacket_suite.smb_enum_shares": "smb_enum_shares",
    "auxiliaries.impacket_suite.smb_read_file": "smb_read_file",
    "auxiliaries.amass.run_amass": "amass",
    "auxiliaries.archived_urls.run_archived_urls": "archived_urls",
    "auxiliaries.cert_tools.run_cert_tools": "cert_tools",
    "auxiliaries.radare2.run_radare2": "radare2",
    "auxiliaries.jadx.run_jadx": "jadx",
    "auxiliaries.playwright_recon.run_playwright_recon": "pw_recon",
    "auxiliaries.playwright_sidecar.run_playwright_sidecar": "pw_sidecar",
    "auxiliaries.burp_mcp.run_burp_mcp": "burp_mcp",
    "auxiliaries.zap.run_zap": "zap",
    "auxiliaries.framework_status.run_framework_status": "framework_status",
    "auxiliaries.program_scope.search_programs": "scope_search_programs",
    # payloads/
    "payloads.ffuf.run_ffuf": "ffuf_payload",
    "payloads.hydra.run_hydra": "hydra",
    "payloads.sqlmap.run_sqlmap": "sqlmap",
    "payloads.hash_crack.run_hash_crack": "hash_crack",
    "payloads.searchsploiting.search_exploit": "searchsploit",
    "payloads.js_recon.run_js_recon": "js_recon",
    "payloads.wordlists.run_wordlists": "wordlists",
    "payloads.metasploiting.MetasploitClient.index_modules": "msf_index",
    "payloads.metasploiting.MetasploitClient.dispatch_metasploit": "msf_dispatch",
    "payloads.metasploiting.MetasploitClient.get_options": "msf_options",
    "payloads.metasploiting.MetasploitClient.set_payload": "msf_set_payload",
    "payloads.metasploiting.MetasploitClient.list_sessions": "msf_sessions",
    "payloads.metasploiting.MetasploitClient.interact_session": "msf_interact",
    "payloads.metasploiting.MetasploitClient.close_msf_session": "msf_close",
    "payloads.msfvenom_tools.generate_payload": "msfvenom",
    "payloads.msfvenom_tools.msfvenom_menu": "msfvenom_menu",
    "payloads.msfvenom_tools.list_dropbox": "list_dropbox",
    "payloads.fastcgi.run_fastcgi": "fastcgi",
    # listeners/
    "listeners.listening.TCPListener.open_listener": "listen_tcp",
    "listeners.listening.TCPListener.close_listener": "close_listener",
    "listeners.listening.TCPListener.send_to_brain": "send_to_brain",
    "listeners.raw_scan.syn_scan": "syn_scan",
    "listeners.collaborator.run_collaborator": "collaborator",
    "listeners.execution_tracker.run_execution_tracker": "execution_tracker",
    "listeners.brain_control.run_brain_control": "brain_control",
    # utils/
    "utils.memory_tools.remember_text": "remember",
    "utils.memory_tools.search_text": "mem_search",
    "utils.memory_tools.recall_text": "mem_recall",
    "utils.memory_tools.get_text": "mem_get",
    "utils.memory_tools.forget_text": "mem_forget",
    "utils.session_manager.list_sessions": "list_sessions",
    "utils.cookie_jar.jar_state": "jar_state",
    "utils.cookie_jar.jar_store_cookie": "jar_store_cookie",
    "utils.cookie_jar.jar_store_token": "jar_store_token",
    "utils.cookie_jar.jar_clear": "jar_clear",
    "utils.cookie_jar.jar_cookie_header": "jar_cookie_header",
    "auxiliaries.web_session.session_get": "session_get",
    "auxiliaries.web_session.session_post": "session_post",
    "auxiliaries.web_session.session_request": "session_request",
    "auxiliaries.web_session.session_upload": "session_upload",
    "utils.findings.report_finding": "report_finding",
    "utils.findings.list_findings": "list_findings",
    "utils.log_reader.read_logs": "read_logs",
}

# Prefixes stripped during auto-derivation of short aliases.
_ALIAS_STRIP_PREFIXES = ("run_", "check_", "exec_", "do_", "perform_")
# Suffixes stripped during auto-derivation.
_ALIAS_STRIP_SUFFIXES = ("_tool",)


def _derive_alias(module_id: str) -> str:
    """Derive a short alias from a ``module_id`` when no curated one exists.

    Strategy: take the last dotted segment, strip common verb prefixes and
    ``_tool`` suffixes, and if it's a method on a class (``Class.method``),
    prefer the method name alone — unless it's generic (``run``, ``check``,
    ``list``), in which case prefix with a snake-cased class name.

    Collisions are *not* resolved here — the caller collects all aliases and
    de-duplicates by appending a module qualifier when two tools claim the
    same short name.
    """
    parts = module_id.split(".")
    last = parts[-1]

    # Strip common prefixes
    for pfx in _ALIAS_STRIP_PREFIXES:
        if last.startswith(pfx):
            last = last[len(pfx):]
            break
    # Strip common suffixes
    for sfx in _ALIAS_STRIP_SUFFIXES:
        if last.endswith(sfx):
            last = last[: -len(sfx)]
            break

    # If the last segment is too generic and there's a class name before it,
    # qualify with the class.
    if last.lower() in ("run", "check", "list", "exec", "scan", "status", "info") and len(parts) >= 3:
        cls_seg = parts[-2]
        last = f"{cls_seg.lower()}_{last}"

    return last


def build_tool_aliases(manifests: List[ToolManifest]) -> Dict[str, ToolManifest]:
    """Return ``{alias: manifest}`` for all discovered tools.

    Curated aliases from ``_TOOL_ALIASES`` win.  Unmatched tools get
    auto-derived aliases.  Collisions are resolved by appending the
    top-level module name (``auxiliaries``, ``payloads``, etc.) as a
    prefix — if that *also* collides, append a numeric suffix.
    """
    result: Dict[str, ToolManifest] = {}
    # First pass: curated aliases (explicit, may collide → resolved later)
    pending: List[tuple] = []  # (alias, manifest)
    for m in manifests:
        curated = _TOOL_ALIASES.get(m.module_id)
        if curated:
            pending.append((curated, m))
        else:
            pending.append((_derive_alias(m.module_id), m))

    for alias, m in pending:
        if alias not in result:
            result[alias] = m
            continue
        # Collision — prefix with the top-level module segment
        top = m.module_id.split(".")[0]
        qualified = f"{top}_{alias}"
        if qualified not in result:
            result[qualified] = m
            continue
        # Still colliding — numeric suffix
        i = 2
        while f"{qualified}_{i}" in result:
            i += 1
        result[f"{qualified}_{i}"] = m
    return result


def _schema_type_to_py(schema_type: str) -> type:
    """Map a JSON-schema type string to a Python type for ``Signature``."""
    if schema_type in ("integer", "int"):
        return int
    if schema_type in ("number", "float"):
        return float
    if schema_type in ("boolean", "bool"):
        return bool
    if schema_type in ("array", "list"):
        return list
    if schema_type in ("object", "dict"):
        return dict
    return str


def _build_signature(manifest: ToolManifest) -> inspect.Signature:
    """Build an ``inspect.Signature`` from the manifest's parameter schema.

    Required parameters become positional-or-keyword with no default;
    optional parameters get ``None`` as a sentinel default.  Each parameter
    carries an ``annotation`` from the schema type, so IPython's tooltip
    shows ``target: str``, ``port: int``, etc.
    """
    if not manifest.parameters:
        return inspect.Signature()
    props = manifest.parameters.get("properties", {})
    required = set(manifest.parameters.get("required", []))
    params: List[inspect.Parameter] = []
    # Required first (so positional order matches declaration), then optional
    ordered = sorted(props.items(), key=lambda kv: (kv[0] not in required, kv[0]))
    for pname, pdef in ordered:
        stype = pdef.get("type", "string") if isinstance(pdef, dict) else "string"
        py_type = _schema_type_to_py(stype)
        default = inspect.Parameter.empty if pname in required else None
        params.append(
            inspect.Parameter(
                pname,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=py_type,
            )
        )
    return inspect.Signature(params)


def _build_docstring(manifest: ToolManifest) -> str:
    """Assemble a readable ``__doc__`` from the manifest's semantic capability
    and per-parameter descriptions.

    This is what ``tool?`` prints in IPython — the operator's quick reference.
    """
    lines = [manifest.internal_semantic_capability.strip(), ""]
    lines.append(f"    tool_id:    {manifest.module_id}")
    lines.append(f"    transport:  {manifest.transport.value}")
    lines.append(f"    path:        {manifest.implementation_path}")
    if manifest.tags:
        lines.append(f"    tags:        {', '.join(manifest.tags)}")
    if manifest.parameters:
        props = manifest.parameters.get("properties", {})
        required = set(manifest.parameters.get("required", []))
        if props:
            lines.append("")
            lines.append("    Parameters")
            lines.append("    ----------")
            for pname, pdef in props.items():
                stype = pdef.get("type", "string") if isinstance(pdef, dict) else "string"
                req = "*" if pname in required else " "
                desc = (pdef.get("description", "") if isinstance(pdef, dict) else "")[:80]
                lines.append(f"    {req} {pname} : {stype}  {desc}".rstrip())
    if manifest.next:
        lines.append("")
        lines.append("    Next steps")
        lines.append("    ----------")
        for hint in manifest.next:
            lines.append(f"    → {hint}")
    return "\n".join(lines)


def _make_tool_wrapper(manifest: ToolManifest, manifests_list: List[ToolManifest]):
    """Create an ``async def`` closure that dispatches a single tool through
    ``run_tool`` with a real ``Signature`` and ``__doc__``.

    The wrapper accepts ``**kwargs`` at the Python level but advertises its
    signature via ``__signature__`` so IPython/Jedi complete the named
    parameters.  Unknown kwargs are passed straight to ``run_tool``, which
    sends them through preflight validation — bad keys are rejected there,
    not silently dropped.
    """
    tool_id = manifest.module_id
    sig = _build_signature(manifest)
    doc = _build_docstring(manifest)

    async def _wrapper(**kwargs):
        return await run_tool(tool_id, kwargs, manifests_list)

    # Attach the metadata that makes IPython completions + introspection work
    _wrapper.__name__ = _TOOL_ALIASES.get(tool_id) or _derive_alias(tool_id)
    _wrapper.__qualname__ = _wrapper.__name__
    _wrapper.__doc__ = doc
    _wrapper.__signature__ = sig
    # Stash the manifest for tools that want to introspect the wrapper
    _wrapper.__manifest__ = manifest  # type: ignore[attr-defined]
    return _wrapper


def build_ipython_namespace(
    manifests: List[ToolManifest],
) -> Dict[str, Any]:
    """Build the full kitted-out IPython user namespace.

    Returns a dict suitable for ``IPython.embed(user_ns=...)`` containing:
      • One ``async def`` wrapper per discovered tool, keyed by short alias
      • ``manifests`` — the flat list (still available for advanced use)
      • ``manifest_by_id(id)`` — lookup helper
      ``registry`` — bare executor instance
      • ``run_tool``, ``discover_tools``, ``resolve_callable`` — raw helpers
      • ``ToolManifest``, ``ToolRegistry`` — model classes
      • ``tools`` — ``{alias: wrapper}`` dict (same objects as the top-level
        aliases, collected for ``tools.<Tab>`` browsing)
      • ``sessions()``, ``scope_on()``, ``scope_off()``, ``scope_status()``,
        ``scope_search()`` — operator command wrappers
    """
    ns: Dict[str, Any] = {}

    # ── Tool wrappers ───────────────────────────────────────────────────
    alias_map = build_tool_aliases(manifests)
    tools: Dict[str, Any] = {}
    for alias, m in alias_map.items():
        wrapper = _make_tool_wrapper(m, manifests)
        ns[alias] = wrapper
        tools[alias] = wrapper
    ns["tools"] = tools
    ns["manifests"] = manifests
    ns["registry"] = _make_executor()

    def manifest_by_id(tool_id: str) -> Optional[ToolManifest]:
        """Look up a manifest by its full ``module_id``."""
        return next((m for m in manifests if m.module_id == tool_id), None)
    ns["manifest_by_id"] = manifest_by_id

    # ── Raw helpers (unchanged from the old namespace) ──────────────────
    ns["run_tool"] = run_tool
    ns["discover_tools"] = discover_tools
    ns["resolve_callable"] = resolve_callable
    ns["ToolManifest"] = ToolManifest
    ns["ToolRegistry"] = ToolRegistry

    # ── Operator command wrappers (sync, print directly) ────────────────
    # These wrap the existing REPL command bodies so the operator has the
    # same control surface inside IPython without typing ``!`` shell escapes.

    def _sessions():
        """Show Brain-held (shared) vs REPL-local sessions — same as the ``sessions`` REPL command."""
        # _sessions_command is async; run it in the current loop via ensure_future
        import asyncio as _a
        try:
            loop = _a.get_event_loop()
        except RuntimeError:
            loop = _a.new_event_loop()
            _a.set_event_loop(loop)
        # If we're inside IPython's autoawait loop, create_task works; otherwise
        # run_until_complete in a fresh loop.  Using a coroutine wrapper keeps
        # it simple — the operator types ``sessions()`` (no await).
        coro = _sessions_command(manifests)
        if loop.is_running():
            task = loop.create_task(coro)
            # IPython's autoawait would normally handle this, but since this is
            # a sync wrapper, we use run_until_complete on a nested loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pool.submit(_a.run, coro).result()
        else:
            loop.run_until_complete(coro)
    ns["sessions"] = _sessions

    def _scope_on(handle: str, platform: str = "h1", strict: bool = True,
                  ip_boundary: bool = False):
        """Arm the packet-scope gate.  Operator-only — not exposed to the agent.

        Example::

            scope_on("starbucks", platform="h1")
        """
        flags = []
        if not strict:
            flags.append("--no-strict")
        if ip_boundary:
            flags.append("--ip-boundary")
        flags.append(f"--platform={platform}")
        rest = f"on {handle} {' '.join(flags)}"
        _scope_command(rest)
    ns["scope_on"] = _scope_on

    def _scope_off():
        """Disarm the packet-scope gate (lab mode — sends unrestricted)."""
        _scope_command("off")
    ns["scope_off"] = _scope_off

    def _scope_status():
        """Show the armed state, asset counts, and manifest age."""
        _scope_command("status")
    ns["scope_status"] = _scope_status

    def _scope_search(query: str, platform: str = "all", assets: bool = False,
                      handle: str = "", refresh: bool = False, limit: int = 10,
                      as_json: bool = False):
        """Query bug-bounty boards for matching programs.

        Example::

            scope_search("starbucks", assets=True)
        """
        flags = [f"--platform={platform}", f"--limit={limit}"]
        if assets:
            flags.append("--assets")
        if handle:
            flags.append(f"--handle={handle}")
        if refresh:
            flags.append("--refresh")
        if as_json:
            flags.append("--json")
        rest = f"search {query} {' '.join(flags)}"
        _scope_command(rest)
    ns["scope_search"] = _scope_search

    # Live keybinding diagnostic: shows what the ESC chord dispatches to in
    # the currently-running prompt.  Usage: check_trigger(shell or get_ipython())
    def check_trigger(shell=None):
        """Show which handler the trigger chord dispatches to (live check)."""
        if shell is None:
            try:
                shell = get_ipython()  # noqa: F821 — defined inside IPython
            except NameError:
                print("  pass the shell: check_trigger(get_ipython())")
                return
        pt = getattr(shell, "pt_app", None)
        if pt is None:
            print("  pt_app not initialized yet — press a key first")
            return
        spec = _trigger_key_spec()
        from prompt_toolkit.keys import Keys as _K
        def _resolve(tok):
            if tok.startswith("c-"):
                return getattr(_K, "Control" + tok[2:].upper(), tok)
            return _K.Escape if tok == "escape" else tok
        keys = tuple(
            getattr(k, "value", k) if isinstance(getattr(k, "value", k), str) else k
            for k in map(_resolve, spec)
        )
        matches = pt.app.key_bindings.get_bindings_for_keys(keys)
        print(f"  chord {spec} resolves to: {[getattr(m.handler, '__name__', '?') for m in matches]}")
    ns["check_trigger"] = check_trigger

    return ns


# ── IPython bottom toolbar + globals overlay + rprompt ───────────────────────
#
# These are pure prompt_toolkit decorations layered on top of IPython's
# existing ``pt_app`` (a ``PromptSession``).  No Jupyter, no kernel — just
# ``FormattedText`` callables and a ``KeyBindings`` entry.
#
#   • ``_bottom_toolbar(shell)`` — re-renders every keystroke; shows cursor
#     line:col, count of user-assigned globals, scope-armed marker, and the
#     word under cursor if it matches a tool alias (so you see the tool's
#     manifest snippet while typing its name).
#   • ``_rprompt(shell)`` — right-aligned next to the input line; when the
#     cursor is inside ``alias(``, shows the remaining **required** params
#     with their types — the same info as ``tool?`` but live and contextual.
#   • F1 keybinding — prints a formatted dump of all user globals (the
#     variables set above the current cell) above the active prompt.
#   • Syntax highlighting — IPython's ``IPythonPTLexer`` (Pygments
#     ``PythonLexer``) is already wired into ``pt_app``; the only reason
#     colours are off is ``InteractiveShellEmbed`` defaults to
#     ``colors="nocolor"``.  Passing ``colors="linux"`` flips the Pygments
#     style on.

import builtins as _builtins

# Env knobs for the toolbar / globals display.
_IPYTHON_COLORS = os.getenv("IPYTHON_COLORS", "linux")  # linux|neutral|lightbg|nocolor|pride|gruvbox-dark
_IPYTHON_TOOLBAR_ENABLED = os.getenv("IPYTHON_TOOLBAR", "1").lower() not in ("0", "false", "no", "off")
_IPYTHON_RPROMPT_ENABLED = os.getenv("IPYTHON_RPROMPT", "1").lower() not in ("0", "false", "no", "off")
# Max globals shown in the toolbar's compact line (F1 shows all).
_IPYTHON_TOOLBAR_MAX_VARS = int(os.getenv("IPYTHON_TOOLBAR_MAX_VARS", "6"))
# Max repr length per variable in the toolbar.
_IPYTHON_TOOLBAR_REPR_LEN = int(os.getenv("IPYTHON_TOOLBAR_REPR_LEN", "20"))
# Mouse support: click to position cursor inside the input buffer.
# Tradeoff: when ON, the terminal's native drag-to-select is captured by
# the app — hold Shift while dragging to force terminal-native selection
# (works in GNOME Terminal, iTerm2, Windows Terminal, Konsole, etc.).
_IPYTHON_MOUSE_SUPPORT = os.getenv("IPYTHON_MOUSE", "1").lower() not in ("0", "false", "no", "off")


def _user_globals(shell) -> List[tuple]:
    """Return ``[(name, value), ...]`` for user-assigned globals in the shell.

    Filters out dunder names, callables (tool wrappers, functions), classes,
    modules, and IPython internals (``__name__``, ``In``, ``Out``, etc.).
    Sorted by insertion order approximation (Python 3.7+ dicts preserve it;
    ``user_ns`` is a regular dict).
    """
    ns = shell.user_ns
    _skip = {"__builtin__", "__builtins__", "_", "__", "___", "_dh",
             "_ih", "_oh", "_sh", "In", "Out", "exit", "quit",
              "get_ipython", "user_ns", "tools", "manifests", "registry"}
    result = []
    for k, v in ns.items():
        if k.startswith("_") or k in _skip:
            continue
        if callable(v) and not hasattr(v, "__manifest__"):
            continue
        import types as _types_mod
        if isinstance(v, type) or isinstance(v, _types_mod.ModuleType):
            continue
        # Skip the tool-wrapper callables (they carry __manifest__)
        if hasattr(v, "__manifest__"):
            continue
        result.append((k, v))
    return result


def _cell_local_vars(cell_text: str, cursor_row: int = -1) -> List[tuple]:
    """Extract variable names assigned in the current (unexecuted) cell text.

    Uses ``ast`` to walk assignment targets — ``ast.parse`` is safe on
    incomplete code because we append a dummy line so the parser sees a
    complete module.  Returns ``[(name, preview_str), ...]`` sorted by
    line number, where ``preview_str`` is a best-effort literal preview
    (the RHS source text truncated, since we can't eval unexecuted code).

    Only names assigned **before** ``cursor_row`` (if given) are returned —
    you don't want completions for variables defined below your cursor.
    """
    import ast as _ast

    # Pad with a newline so an incomplete last line doesn't break the parser
    text = cell_text
    if not text.endswith("\n"):
        text += "\n"

    try:
        tree = _ast.parse(text)
    except SyntaxError:
        # Try wrapping in a try block — handles bare ``await`` at top level
        # which is only valid inside async def.  IPython rewrites it, but ast
        # doesn't.  Fallback: regex for ``name =`` patterns.
        return _cell_local_vars_regex(cell_text, cursor_row)

    results = []
    for node in _ast.iter_child_nodes(tree):
        if isinstance(node, _ast.Assign):
            # ``x = 42`` → targets are Names
            for target in node.targets:
                if isinstance(target, _ast.Name):
                    if cursor_row >= 0 and node.lineno > cursor_row + 1:
                        continue
                    rhs = _ast.get_source_segment(text, node) or ""
                    # Strip the ``name = `` prefix for the preview
                    eq_idx = rhs.find("=")
                    preview = rhs[eq_idx + 1:].strip() if eq_idx >= 0 else "?"
                    if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                        preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                    results.append((target.id, preview))
        elif isinstance(node, _ast.AnnAssign):
            # ``x: int = 42``
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                if node.value is not None:
                    rhs = _ast.get_source_segment(text, node) or ""
                    eq_idx = rhs.find("=")
                    preview = rhs[eq_idx + 1:].strip() if eq_idx >= 0 else "?"
                    if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                        preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                    results.append((node.target.id, preview))
        elif isinstance(node, (_ast.AugAssign,)):
            # ``x += 1`` — x must already exist, but we still track it
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                results.append((node.target.id, "<aug>"))
        # ``with ... as x:`` and ``for x in ...:`` targets
        elif isinstance(node, _ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, _ast.Name):
                    if cursor_row >= 0 and node.lineno > cursor_row + 1:
                        continue
                    results.append((item.optional_vars.id, "<with>"))
        elif isinstance(node, _ast.For):
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                results.append((node.target.id, "<loop>"))

    return results


def _cell_local_vars_regex(cell_text: str, cursor_row: int = -1) -> List[tuple]:
    """Fallback regex-based extraction when ``ast.parse`` fails.

    Catches ``name = ...`` and ``name: type = ...`` patterns.  Less accurate
    than AST (misses unpacking, ignores indentation context) but handles
    incomplete code with bare ``await`` that ast.parse rejects.
    """
    import re as _re

    results = []
    lines = cell_text.split("\n")
    for i, line in enumerate(lines):
        if cursor_row >= 0 and i > cursor_row:
            break
        # ``name = value`` or ``name: type = value`` — top-level (no leading
        # whitespace) or indented inside a block we don't track.
        m = _re.match(r"^(\w+)\s*(?::\s*\S+)?\s*=\s*(.+)", line)
        if m:
            name = m.group(1)
            preview = m.group(2).strip()
            if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
            results.append((name, preview))
    return results


def _cell_overview(cell_text: str, max_lines: int = 3) -> str:
    """Compact one-line overview of the current cell.

    Shows the first non-empty line (truncated) and the total line count.
    If the cell is multi-line, includes a ``… (+N lines)`` suffix.
    """
    lines = cell_text.split("\n")
    # Find the first non-empty, non-comment line
    first = ""
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            first = stripped
            break
    if not first:
        first = lines[0].strip() if lines else ""
    if len(first) > 40:
        first = first[:37] + "…"
    total = len(lines)
    if total > 1:
        return f"{first} … (+{total - 1}L)"
    return first


def _bottom_toolbar(shell):
    """Bottom status bar: cursor position + cell-local vars + globals + status.

    Returns ``FormattedText`` (list of ``(style, text)`` tuples) that
    prompt_toolkit re-renders on every keystroke via ``bottom_toolbar``.

    The toolbar shows **two tiers** of variables:
      1. **Cell-local** (uncommitted) — names assigned in the current cell
         text above the cursor, parsed via ``ast``.  These aren't in
         ``user_ns`` yet (the cell hasn't executed) but they're what you're
         actively working with.  Rendered in a distinct colour.
      2. **Globals** (committed) — variables in ``user_ns`` from previously
         executed cells.  The existing behaviour.
    """
    from prompt_toolkit.formatted_text import FormattedText

    parts = []
    cell_text = ""
    cursor_row = -1

    # ── Cursor position + cell overview ────────────────────────────────
    try:
        buf = shell.pt_app.app.current_buffer
        doc = buf.document
        row = doc.cursor_position_row + 1
        col = doc.cursor_position_col + 1
        cell_text = buf.text
        cursor_row = doc.cursor_position_row
        parts.append(("class:toolbar.cursor", f" L{row}:C{col} "))
        if cell_text.strip():
            overview = _cell_overview(cell_text)
            parts.append(("class:toolbar.cell", f" [{overview}] "))
    except Exception:
        parts.append(("", " L-:C- "))

    # ── Cell-local (uncommitted) variables ─────────────────────────────
    if cell_text.strip():
        try:
            cell_vars = _cell_local_vars(cell_text, cursor_row)
            if cell_vars:
                parts.append(("class:toolbar.cellvars", f" {len(cell_vars)} in-cell "))
                previews = []
                for name, preview in cell_vars[:_IPYTHON_TOOLBAR_MAX_VARS]:
                    previews.append(f"{name}={preview}")
                preview_str = "  ".join(previews)
                if len(cell_vars) > _IPYTHON_TOOLBAR_MAX_VARS:
                    preview_str += " …"
                parts.append(("class:toolbar.cellpreview", f" {preview_str} "))
        except Exception:
            pass

    # ── Committed globals count + compact preview ──────────────────────
    try:
        globs = _user_globals(shell)
        parts.append(("class:toolbar.vars", f" {len(globs)} globals "))
        if globs:
            recent = globs[-_IPYTHON_TOOLBAR_MAX_VARS:]
            previews = []
            for name, val in recent:
                try:
                    rv = repr(val)
                except Exception:
                    rv = "<?>"
                if len(rv) > _IPYTHON_TOOLBAR_REPR_LEN:
                    rv = rv[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                previews.append(f"{name}={rv}")
            preview_str = "  ".join(previews)
            if len(globs) > _IPYTHON_TOOLBAR_MAX_VARS:
                preview_str += " …"
            parts.append(("class:toolbar.preview", f" {preview_str} "))
    except Exception:
        pass

    # ── Scope-armed marker ─────────────────────────────────────────────
    try:
        from utils.scope_gate import is_armed as _is_armed
        if _is_armed():
            parts.append(("class:toolbar.scope", " [SCOPE ARMED] "))
    except Exception:
        pass

    # ── Brain socket status ────────────────────────────────────────────
    try:
        sock = Path("/tmp/brain.sock")
        if sock.exists():
            parts.append(("class:toolbar.brain", " brain:✓ "))
        else:
            parts.append(("class:toolbar.brain.down", " brain:✗ "))
    except Exception:
        pass

    return FormattedText(parts)


def _rprompt(shell):
    """Right-prompt: show remaining required params when inside a tool call.

    Detects ``alias(`` in the text before the cursor and, if the alias is a
    known tool wrapper, renders the **required** params that haven't been
    supplied yet — live, right-aligned on the input line.
    """
    from prompt_toolkit.formatted_text import FormattedText

    try:
        buf = shell.pt_app.app.current_buffer
        text = buf.document.text_before_cursor
    except Exception:
        return FormattedText([])

    # Find the last unclosed ``(`` — are we inside a call?
    paren_depth = 0
    open_paren_idx = -1
    for i, ch in enumerate(text):
        if ch == "(":
            paren_depth += 1
            open_paren_idx = i
        elif ch == ")":
            paren_depth -= 1
    if paren_depth <= 0 or open_paren_idx < 0:
        return FormattedText([])

    # Extract the word immediately before the ``(`` (the function/alias name)
    before_paren = text[:open_paren_idx]
    # Strip trailing whitespace
    stripped = before_paren.rstrip()
    if not stripped:
        return FormattedText([])
    # Walk backwards to the first non-identifier char
    end = len(stripped)
    start = end
    while start > 0 and (stripped[start - 1].isalnum() or stripped[start - 1] == "_"):
        start -= 1
    alias = stripped[start:end]
    if not alias:
        return FormattedText([])

    # Strip a leading ``await`` — the alias is the word after it
    if alias == "await":
        remainder = stripped[:start].rstrip()
        end2 = len(remainder)
        start2 = end2
        while start2 > 0 and (remainder[start2 - 1].isalnum() or remainder[start2 - 1] == "_"):
            start2 -= 1
        alias = remainder[start2:end2]

    if not alias:
        return FormattedText([])

    # Look up the tool wrapper in user_ns
    wrapper = shell.user_ns.get(alias)
    if wrapper is None or not hasattr(wrapper, "__manifest__"):
        return FormattedText([])

    manifest = wrapper.__manifest__
    if not manifest.parameters:
        return FormattedText([])

    props = manifest.parameters.get("properties", {})
    required = set(manifest.parameters.get("required", []))
    if not required:
        return FormattedText([])

    # Which required params have already been supplied?
    args_section = text[open_paren_idx + 1:]
    supplied = set()
    for pname in props:
        if f"{pname}=" in args_section or f"{pname} =" in args_section:
            supplied.add(pname)

    missing = [p for p in required if p not in supplied]
    if not missing:
        return FormattedText([("class:rprompt.done", " ✓ all required ")])

    # Build the hint: ``target: str, options: str``
    pieces = []
    for pname in missing:
        pdef = props.get(pname, {})
        ptype = pdef.get("type", "str") if isinstance(pdef, dict) else "str"
        pieces.append(f"{pname}: {ptype}")
    hint = "  ".join(pieces)
    if len(hint) > 60:
        hint = hint[:57] + "…"

    return FormattedText([
        ("class:rprompt.missing", "missing: "),
        ("class:rprompt.params", hint),
    ])


def _install_toolbar_and_keybindings(shell) -> None:
    """Wire the bottom toolbar, rprompt, and F1 globals overlay into ``shell.pt_app``.

    Called after ``init_prompt_toolkit_cli()`` has created ``pt_app`` (i.e.
    inside ``_embed()``, after the shell is constructed but before the
    interactive loop starts).
    """
    from prompt_toolkit.key_binding import KeyBindings

    pt_app = shell.pt_app
    if pt_app is None:
        return

    # ── Bottom toolbar ─────────────────────────────────────────────────
    if _IPYTHON_TOOLBAR_ENABLED:
        pt_app.bottom_toolbar = lambda: _bottom_toolbar(shell)

    # ── Right prompt (param hints) ─────────────────────────────────────
    if _IPYTHON_RPROMPT_ENABLED:
        pt_app.rprompt = lambda: _rprompt(shell)

    # ── Mouse support: click to position cursor ───────────────────────
    # IPython defaults to mouse_support=False (terminal handles mouse
    # natively → drag-to-select works but click doesn't move the cursor).
    # Setting True enables click-to-position, but captures mouse events so
    # native drag-to-select needs Shift+drag (standard in most terminals).
    if _IPYTHON_MOUSE_SUPPORT:
        pt_app.mouse_support = True

    # ── F1: dump all user globals above the prompt ─────────────────────
    kb = KeyBindings()

    @kb.add("f1")
    def _dump_globals(event):
        """Print all user variables — both cell-local (uncommitted) and globals."""
        # ── Cell-local (uncommitted) variables ─────────────────────────
        try:
            buf = shell.pt_app.app.current_buffer
            cell_text = buf.text
            cursor_row = buf.document.cursor_position_row
            cell_vars = _cell_local_vars(cell_text, cursor_row)
        except Exception:
            cell_vars = []

        if cell_vars:
            print(f"  ── {len(cell_vars)} in-cell variable(s) (uncommitted) ──")
            for name, preview in cell_vars:
                print(f"  {name:25s} := {preview}")
            print()

        # ── Committed globals ──────────────────────────────────────────
        globs = _user_globals(shell)
        if not globs and not cell_vars:
            print("  (no user variables yet)")
            return
        if globs:
            print(f"  ── {len(globs)} global variable(s) (committed) ──")
            for name, val in globs:
                try:
                    rv = repr(val)
                except Exception:
                    rv = "<?>"
                # Truncate long reprs but show enough to be useful
                if len(rv) > 80:
                    rv = rv[:77] + "…"
                # Show the type name for non-trivial values
                tn = type(val).__name__
                print(f"  {name:25s} {tn:6s} = {rv}")
        print()

    # Merge our keybindings with IPython's existing set.
    # ``merge_key_bindings`` produces a ``_MergedKeyBindings`` that checks
    # both registries — the original bindings (Ctrl+L, Ctrl+R, Tab, etc.)
    # stay live, and F1 is added alongside them.
    from prompt_toolkit.key_binding import merge_key_bindings as _merge_kb
    existing_kb = pt_app.key_bindings
    if existing_kb is not None:
        pt_app.key_bindings = _merge_kb([existing_kb, kb])
    else:
        pt_app.key_bindings = kb


def _ipython_toolbar_styles() -> Dict[str, str]:
    """Return Pygments style overrides for the toolbar/rprompt classes.

    Merged into ``shell.highlighting_style_overrides`` so the toolbar's
    ``class:toolbar.*`` and ``class:rprompt.*`` tokens get colours.
    """
    return {
        # Toolbar — dark background, muted text
        "toolbar.cursor": "bg:#333333 fg:#66aaff",
        "toolbar.cell": "bg:#333333 fg:#aa88cc",
        "toolbar.cellvars": "bg:#333333 fg:#ddaa44",
        "toolbar.cellpreview": "bg:#333333 fg:#aa7733",
        "toolbar.vars": "bg:#333333 fg:#66cc66",
        "toolbar.preview": "bg:#333333 fg:#888888",
        "toolbar.scope": "bg:#553333 fg:#ff6666 bold",
        "toolbar.brain": "bg:#333333 fg:#66cc66",
        "toolbar.brain.down": "bg:#333333 fg:#cc6666",
        # Right prompt — dim, right-aligned
        "rprompt.missing": "fg:#cc9933",
        "rprompt.params": "fg:#66aaff",
        "rprompt.done": "fg:#66cc66",
    }


# ── Ollama-powered inline auto-suggest (ghost text) for IPython ─────────────
#
# prompt_toolkit's ``AutoSuggest`` produces the grayed inline "ghost text"
# you see in VS Code.  IPython ships with ``AutoSuggestFromHistory`` (matches
# previous inputs) — this subclass queries the local Ollama model instead,
# so the suggestion knows about framework tool names, signatures, and the
# ``await`` prefix that async wrappers need.
#
# Adaptive backoff design (the concurrency-safe part):
#
#   • Short timeout (``OLLAMA_COMPLETION_TIMEOUT_MS``, default 800ms).
#     If Ollama is busy (secretary agent turn, OWUI chat, embeddings), the
#     request simply times out → no ghost text this keystroke.  The operator
#     keeps typing; the next idle moment catches up.
#   • Circuit breaker: after ``_MAX_CONSECUTIVE_FAILURES`` (3) consecutive
#     timeouts/errors, the suggester goes quiet for ``_BACKOFF_COOLDOWN_S``
#     (30s) before trying again.  This prevents log spam and avoids
#     hammering a busy Ollama with completion requests it can't service.
#   • Minimum prefix: no request is sent until the current line has at least
#     ``_MIN_PREFIX`` (3) characters — avoids firing on every keystroke of a
#     fresh prompt.
#   • Cache: the last ``(line_prefix → suggestion)`` pair is cached.  If the
#     user types a character that extends the cached prefix, the cached
#     suggestion is trimmed and re-used — zero Ollama round-trips.
#   • Thread-pool dispatch: ``get_suggestion`` runs in a worker thread via
#     ``get_suggestion_async`` so it never blocks the prompt's event loop.
#     The sync ``get_suggestion`` uses a short ``threading`` timeout; the
#     async override (which IPython/prompt_toolkit actually calls) uses
#     ``asyncio.wait_for``.
#
# The model is configurable via ``OLLAMA_COMPLETION_MODEL`` (falls back to
# ``SECRETARY_MODEL``, then to ``qwen2.5-coder:7b`` as a sane default — a
# small coder model is fast enough for ghost text and doesn't contend with
# the secretary's own slots).  Disable entirely with
# ``OLLAMA_COMPLETION_ENABLED=0``.

import threading as _threading_mod

# On-demand Ollama inline completion for the IPython REPL.  Uses IPython's
# own NavigableAutoSuggestFromHistory (provisional in 8.32+) — history ghost
# text is automatic, The trigger key fires an Ollama completion on demand.  No
# prompt freezing because the LLM query is on-demand, not per-keystroke.
# Disable with OLLAMA_COMPLETION_ENABLED=0.
_COMPLETION_ENABLED = os.getenv("OLLAMA_COMPLETION_ENABLED", "1").lower() not in ("0", "false", "no", "off")
_COMPLETION_MODEL = (
    os.getenv("OLLAMA_COMPLETION_MODEL")
    or os.getenv("SECRETARY_MODEL")
    or "qwen2.5-coder:7b"
)
_COMPLETION_TIMEOUT_MS = int(os.getenv("OLLAMA_COMPLETION_TIMEOUT_MS", "6000"))
_COMPLETION_MIN_PREFIX = int(os.getenv("OLLAMA_COMPLETION_MIN_PREFIX", "3"))
_COMPLETION_MAX_FAILURES = 5
_COMPLETION_BACKOFF_COOLDOWN_S = 15.0
# Token budget for on-demand suggestions. 400 leaves room for a useful
# multiline block without making the shared Ollama model reserve a larger
# completion budget than necessary.
_COMPLETION_NUM_PREDICT = int(os.getenv("OLLAMA_COMPLETION_NUM_PREDICT", "400"))
# Bound the per-request KV cache and keep the model resident briefly so the
# IPython and Open WebUI lanes can reuse the same loaded weights.
_COMPLETION_NUM_CTX = int(os.getenv("OLLAMA_COMPLETION_NUM_CTX", "4096"))
_COMPLETION_KEEP_ALIVE = os.getenv("OLLAMA_COMPLETION_KEEP_ALIVE", "5m")
# Max characters of typed context sent to the model (whole buffer: previous
# lines + the current line — variables from earlier lines are what let the
# model suggest code that uses them instead of inventing placeholders).
_COMPLETION_MAX_CONTEXT_CHARS = int(os.getenv("OLLAMA_COMPLETION_MAX_CONTEXT_CHARS", "4000"))
# Max chars of text AFTER the cursor sent to the model.  The closing
# brackets / dedent / following lines tell the model what construct it's
# inside (e.g. ``]`` after a blank line inside ``payloads = [``).  Without
# this the model only sees the prefix and doesn't know what to complete to.
_COMPLETION_MAX_AFTER_CHARS = int(os.getenv("OLLAMA_COMPLETION_MAX_AFTER_CHARS", "500"))
# Cursor marker inserted between before-cursor and after-cursor text in the
# FIM (fill-in-the-middle) prompt.  Coder models are trained on this pattern;
# non-coder models still understand it as "continue here".  The marker must
# be distinctive enough that the model doesn't echo it back — ``<CURSOR>``
# is unambiguous and rarely appears in real code.
_COMPLETION_CURSOR_MARKER = os.getenv("OLLAMA_COMPLETION_CURSOR_MARKER", "\n<CURSOR>\n")
_COMPLETION_MAX_FAILURES = 5
_COMPLETION_BACKOFF_COOLDOWN_S = 15.0
# Debounce: wait this many ms after the last keystroke before firing an
# Ollama request.  Without this, every keystroke triggers a 1-3s request
# and the prompt freezes.  With it, only the *final* text after a burst of
# typing triggers a request — the user types without lag, and the ghost
# text appears ~400ms after they pause.
_COMPLETION_DEBOUNCE_MS = int(os.getenv("OLLAMA_COMPLETION_DEBOUNCE_MS", "400"))
# Max cold-start timeouts before the circuit breaker opens.  Each cold-start
# attempt uses the longer timeout (10s+); after this many failures the model
# isn't loading (wrong name, Ollama down, VRAM exhausted) and we stop
# retrying to avoid hanging the prompt on every keystroke.
_COLD_START_MAX_ATTEMPTS = 3
# Max tool aliases included in the completion system prompt.  190+ tools at
# ~15 chars each is ~3KB — fine for a 14B model's context window.  Set to 0
# for no limit.
_COMPLETION_MAX_TOOLS = int(os.getenv("OLLAMA_COMPLETION_MAX_TOOLS", "250"))
# Think control for reasoning models (GLM, deepseek-r1, qwen3 …).  Ollama's
# /api/chat takes a top-level ``think`` parameter (bool or thinking level).
# Suggester calls always send think=False by default: a reasoning model that
# buries its budget in message.thinking returns EMPTY content and no ghost
# text (verified against glm-4.7-flash).  Set to "low"|"medium"|"high" to use
# a thinking level instead, or "auto"/unset to omit the parameter entirely
# (older Ollama versions reject unknown fields).
_COMPLETION_THINK = os.getenv("OLLAMA_COMPLETION_THINK", "false").strip().lower()
# Trigger chord for the on-demand Ollama suggestion.  Every Ctrl+letter is
# bound by IPython/prompt_toolkit defaults; Ctrl+digits are nominally free
# but several terminals remap or swallow them (verified: c-7 arrives as
# backspace / c-h on this driver).  A two-key ESC-prefixed chord is robust:
# "escape c-o" sends 0x1b 0x0f — unambiguous, free at both binding layers,
# and can never trigger the bare c-o "open in editor" binding because the
# parser sees the two-key sequence.  Env override accepts ONE key spec
# ("c-5", "f5") or a SPACE-separated chord ("escape c-o", "c-x c-o").
# NOTE: ESC-prefixed chords ("escape c-o") require the second key to arrive
# while ESC is still the pending prefix; press-ESC-release-then-Ctrl+O
# collapses to a solo Escape press and the bare c-o editor binding fires
# instead ("does both" symptom, 2026-10-09).  c-x prefix chords have no such
# timing dependency — c-x is a dedicated emacs prefix key.
_COMPLETION_TRIGGER_KEY = os.getenv("OLLAMA_COMPLETION_TRIGGER_KEY", "c-x c-o")


def _trigger_key_spec() -> List[str]:
    """Parse the trigger-key env value into a prompt_toolkit key list."""
    return [k.strip() for k in _COMPLETION_TRIGGER_KEY.split() if k.strip()]


def _ollama_chat_url() -> str:
    """Derive the Ollama ``/api/chat`` endpoint from ``OLLAMA_BASE_URL``.

    ``OLLAMA_BASE_URL`` is the OpenAI-compatible endpoint (``.../v1``).
    Ollama's native chat API lives at ``.../api/chat`` (no ``/v1``).
    """
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base.rstrip("/") + "/api/chat"


def _ollama_query_sync(model: str, system: str, typed_context: str, url: str,
                       timeout_s: float,
                       num_predict: int = _COMPLETION_NUM_PREDICT,
                       timeout_override_ms: Optional[int] = None) -> Optional[str]:
    """Synchronous Ollama chat request.  Returns the raw completion text or
    ``None`` on any failure.  Always called from a worker thread.

    ``typed_context`` is the text to continue — the whole buffer up to the
    cursor (previous lines included), so the model can suggest code that
    uses variables the operator already typed instead of inventing
    placeholder names.
    """
    import urllib.request
    import urllib.error

    timeout_s = (timeout_override_ms or _COMPLETION_TIMEOUT_MS) / 1000.0

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": typed_context},
    ]

    # Assistant priming ("```python\n") forces chat-tuned models to continue
    # inside a code block — but ONLY works when the model actually thinks
    # (the primed fence is part of the think-then-write pattern).  With
    # think=false the model sees a non-sequitur turn and stops immediately
    # with EMPTY content.  So: prime only when think is enabled, otherwise
    # rely on the system prompt + fence stripping.
    thinking_requested = _COMPLETION_THINK in (
        "true", "yes", "1", "low", "medium", "high", "max"
    )
    if thinking_requested:
        messages.append({"role": "assistant", "content": "```python\n"})

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "keep_alive": _COMPLETION_KEEP_ALIVE,
        "options": {
            "num_ctx": _COMPLETION_NUM_CTX,
            "num_predict": num_predict,  # _COMPLETION_NUM_PREDICT (multiline window)
            "temperature": 0.2,
            # `````" keeps the reply inside the primed code block; blank-line
            # stops are dropped — multiline suggestions need real blank lines
            # for indentation.  (With think=true the budget also covers think.)
            # NO stop strings: multi-model testing (2026-10-09) proved
            # stop:["```"] is fatal without assistant priming — most models
            # open their reply WITH a fence, the stop string matches on
            # token 1, and generation halts with an empty payload
            # (qwen3.8:27b: eval_count=1, content="").  Fence cleanup is
            # handled downstream in the reply parsing instead.
            "stop": [],
        },
    }

    # Force no-think on every suggester call (unless overridden).  Reasoning
    # models with think enabled burn their budget in message.thinking and
    # return EMPTY content — no ghost text.  "auto"/"" omits the field for
    # Ollama builds that predate the parameter.
    if _COMPLETION_THINK and _COMPLETION_THINK != "auto":
        payload["think"] = (
            True if _COMPLETION_THINK in ("true", "yes", "1")
            else _COMPLETION_THINK if _COMPLETION_THINK in ("low", "medium", "high", "max")
            else False
        )

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # Socket timeout must exceed the caller's asyncio.wait_for budget so the
    # async timeout fires first (cleaner failure accounting).  +5s headroom.
    _sock_timeout = max(timeout_s + 5.0, 20.0)
    try:
        with urllib.request.urlopen(req, timeout=_sock_timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return None

    msg = body.get("message") or {}
    raw = (msg.get("content") or "").strip()
    if not raw:
        return None

    # Thinking models (GLM flash, deepseek-r1, …) may spend their whole
    # token budget inside <think>…</think> — the visible content is then
    # empty.  Strip the block before deciding the response is useless.
    if "<think>" in raw:
        import re as _re
        raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()
        # Dangling <think> with no closer (budget exhausted mid-reasoning)
        if raw.startswith("<think>"):
            raw = ""

    if not raw:
        return None
    # Strip markdown fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    return raw if raw else None


def _trim_completion(completion: str, typed_prefix: str = "",
                     after_cursor: str = "",
                     before_cursor: str = "") -> str:
    """Clean a model reply into displayable ghost text.

    Multiline-aware: keeps interior lines/indentation (the renderer emits
    them as ghost lines below the prompt), strips markdown fences, removes
    any echo of what the operator already typed (the **whole** before-cursor
    buffer, not just the current line), and strips any echo of the text
    **after** the cursor (the FIM suffix).

    The model was given ``before_cursor`` + ``<CURSOR>`` + ``after_cursor``.
    A well-behaved model outputs only the completion (what goes in the
    cursor's place).  But many models echo part or all of the prefix —
    especially the current line and the last few lines before the cursor.
    We strip echoed prefix lines from the **head** of the completion,
    working backwards line-by-line until we find a line that isn't an echo.
    """
    raw = completion.strip()
    if not raw:
        return ""
    # Strip a full markdown code block if the model re-emitted one
    lines = raw.split("\n")
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    completion = "\n".join(lines).rstrip()
    if not completion:
        return ""

    # Strip echoed before-cursor text from the head of the completion.
    # The model was given the full before_cursor + <CURSOR> + after_cursor.
    # A well-behaved model outputs only what replaces <CURSOR>.  But many
    # models echo part or all of the before-cursor text.  We need to find
    # the longest tail of before_cursor that appears as a head of the
    # completion and strip it.
    #
    # Example: before = "x = 42\nawait nmap("
    #           reply = "x = 42\nawait nmap(target=x)"
    # The echoed prefix is "x = 42\nawait nmap(" — the entire before_cursor.
    # After stripping: "target=x)"
    #
    # Example: before = "x = 42\nawait nmap("
    #           reply = "await nmap(target=x)"
    # The echoed prefix is "await nmap(" — just the last line.
    # After stripping: "target=x)"
    if before_cursor:
        before_lines = before_cursor.split("\n")
        c_lines = completion.split("\n")
        # Find the longest tail of before_cursor that matches a head of the
        # completion.  The model may echo the full prefix or just the last
        # few lines.  The LAST matched line (the "boundary") may be a
        # prefix of the completion line — the model echoed it AND continued
        # it (e.g. ``await nmap(`` → ``await nmap(target=x)``).  In that
        # case we strip the echoed part and keep the continuation.  All
        # earlier matched lines must be exact echoes.
        best_strip_lines = 0
        best_partial_keep = ""  # continuation text from the boundary line
        for start_idx in range(len(before_lines)):
            candidate = before_lines[start_idx:]
            if len(candidate) > len(c_lines):
                continue
            matched = True
            partial_keep = None
            ci = 0  # completion line index (advances separately because
                    # empty before-lines don't consume a completion line)
            for j, b_line in enumerate(candidate):
                b_stripped = b_line.rstrip()
                if not b_stripped:
                    # Empty before-line — don't consume a completion line
                    continue
                if ci >= len(c_lines):
                    matched = False
                    break
                c_line = c_lines[ci]
                if j < len(candidate) - 1:
                    # Non-boundary lines must match exactly
                    if c_line.rstrip() == b_stripped:
                        ci += 1
                        continue
                    matched = False
                    break
                else:
                    # Boundary (last) line: completion may equal it
                    # (exact echo) or start with it (echo + continuation).
                    if c_line.rstrip() == b_stripped:
                        partial_keep = ""  # exact echo, nothing to keep
                        ci += 1
                    elif c_line.startswith(b_stripped):
                        # Model continued the line — keep the continuation
                        partial_keep = c_line[len(b_stripped):]
                        ci += 1
                    else:
                        matched = False
                    break
            if matched and ci > best_strip_lines:
                best_strip_lines = ci
                best_partial_keep = partial_keep or ""

        if best_strip_lines > 0:
            remaining = c_lines[best_strip_lines:]
            if best_partial_keep:
                remaining = [best_partial_keep] + remaining
            completion = "\n".join(remaining).lstrip("\n").rstrip()
            if not completion:
                return ""

    # Fallback: strip the typed prefix (current line only) if the model
    # echoed just that and we didn't catch it above.
    if typed_prefix:
        c_lines = completion.split("\n")
        typed_last = typed_prefix.split("\n")[-1]
        if c_lines and c_lines[0].startswith(typed_last):
            c_lines[0] = c_lines[0][len(typed_last):]
            completion = "\n".join(c_lines).lstrip("\n").rstrip("\n")
    # Strip any echoed after-cursor suffix.  The model was given the text
    # after <CURSOR> as context; a well-behaved model stops before it, but
    # some models reproduce it.  We trim from the first point where the
    # completion's tail matches the after-cursor text's head.
    if after_cursor.strip():
        after_stripped = after_cursor.lstrip()
        # Check if the completion ends with (or contains) the after-cursor text
        if completion.endswith(after_stripped):
            completion = completion[: -len(after_stripped)].rstrip()
        else:
            # Try a partial match — the model may have echoed just the
            # first line of the after-cursor text (e.g. ``]`` or ``)``)
            after_first_line = after_stripped.split("\n")[0].strip()
            if after_first_line and completion.endswith(after_first_line):
                completion = completion[: -len(after_first_line)].rstrip()
    return completion


# ── On-demand Ollama inline completion via IPython's NavigableAutoSuggest ──
#
# IPython 8.32+ has a provisional LLM suggestion API built into
# ``NavigableAutoSuggestFromHistory``.  The design is **on-demand**: the
# operator presses a key (default Ctrl+X then Ctrl+O) to trigger an LLM completion,
# and IPython manages the async task lifecycle — no prompt freezing.
#
# The upstream implementation requires ``jupyter_ai_magics`` and the
# ``jupyter_ai.completions.models`` protocol.  We bypass that entirely by
# subclassing and overriding ``_trigger_llm`` / ``_trigger_llm_core`` to
# call Ollama directly.  No jupyter-ai dependency needed.
#
# History-based ghost text (instant, no Ollama) still works automatically —
# the LLM completion is a separate, on-demand action.

try:
    from IPython.terminal.shortcuts.auto_suggest import (
        NavigableAutoSuggestFromHistory as _NavSuggest,
    )
    _HAS_NAV_SUGGEST = True
except ImportError:
    _HAS_NAV_SUGGEST = False


class OllamaNavigableSuggest(_NavSuggest if _HAS_NAV_SUGGEST else object):
    """``NavigableAutoSuggestFromHistory`` with on-demand Ollama completions.

    History matching works automatically (instant ghost text from IPython
    history).  Press the trigger key (Ctrl+X, Ctrl+O) to trigger an Ollama-powered
    completion that knows about framework tool names and signatures.
    """

    def __init__(self, tool_aliases: List[str],
                 tool_specs: Optional[Dict[str, Dict[str, Any]]] = None):
        super().__init__()
        self._tool_aliases = sorted(tool_aliases)
        self._tool_specs = tool_specs or {}
        self._url = _ollama_chat_url()
        self._model = _COMPLETION_MODEL
        # Timeout scales with the token budget: 512 tok at a conservative
        # 45 tok/s (local 14B, mid-burst) = ~11s of pure generation; +3s
        # overhead for load/queue/prompt-eval.  An explicit
        # OLLAMA_COMPLETION_TIMEOUT_MS in .env overrides the computed value.
        _env_timeout = os.getenv("OLLAMA_COMPLETION_TIMEOUT_MS", "").strip()
        _computed_ms = int(1000 * (_COMPLETION_NUM_PREDICT / 45 + 3))
        self._timeout_s = (int(_env_timeout) if _env_timeout.isdigit()
                           else _computed_ms) / 1000.0
        # Shell handle is wired in by _embed() after the shell exists; the
        # debug flag surfaces otherwise-silent failure paths.  Output goes
        # through patch_stdout so it renders above the active prompt.
        self._shell = None
        self._debug = os.getenv("OLLAMA_COMPLETION_DEBUG", "1").lower() not in ("0", "false", "no", "off")

        # Number of requests issued (stale-response guard)
        self._request_number = 0

        self._system = (
            "You are an inline code-completion engine for a security-testing "
            "REPL. Continue the operator's code at the cursor. "
            "FILL-IN-THE-MIDDLE: the user message contains the code before "
            "the cursor, a <CURSOR> marker showing exactly where to "
            "continue, and the code after the cursor (closing brackets, "
            "following lines). Your output replaces the <CURSOR> marker — "
            "do NOT repeat the text before or after it. Use the text after "
            "the cursor to understand what construct you're inside (a list, "
            "a function body, a dict, etc.) and match its indentation. "
            "OUTPUT RULES: raw Python only — no explanations, no markdown, "
            "no comments, no prose. You may emit MULTIPLE lines (a short "
            "block, 1-8 lines, with correct 4-space indentation) when that "
            "is the natural continuation. Reuse the names of variables the "
            "operator already defined — never invent placeholder names like "
            "target_ip or result1. If you cannot continue the code, output "
            "nothing. "
            "Async tool callables (call with await): "
            + self._tools_list() + ". Use these exact short aliases; never "
            "invent a dotted module path. "
            "Sync operator functions: scope_on, scope_off, scope_status, "
            "scope_search, sessions."
        )

    def _tools_list(self) -> str:
        """Compact alias + parameter catalog for the system prompt."""
        aliases = (self._tool_aliases[:_COMPLETION_MAX_TOOLS]
                   if _COMPLETION_MAX_TOOLS > 0 else self._tool_aliases)
        entries = []
        for alias in aliases:
            schema = self._tool_specs.get(alias) or {}
            properties = schema.get("properties", {})
            required = set(schema.get("required", []))
            params = []
            for name in properties:
                params.append(name + ("*" if name in required else ""))
            entries.append(f"{alias}({', '.join(params)})")
        return ", ".join(entries)

    def _dbg(self, msg: str) -> None:
        """One-line debug print, rendered above the active prompt.

        IPython's ``prompt_for_code`` runs the prompt under prompt_toolkit's
        ``patch_stdout``, which routes prints from tasks/threads through the
        prompt renderer — safe to call from the background LLM task.
        """
        if self._debug:
            print(f"\n[ollama] {msg}", flush=True)

    async def _trigger_llm(self, buffer) -> None:
        """On-demand LLM completion — bypasses the jupyter-ai check.

        Cancels any running LLM task, then starts a new one.  IPython's
        ``@_only_one_at_a_time`` + ``asyncio.create_task`` manages the
        lifecycle — the prompt is not blocked during the request.
        """
        self._cancel_running_llm_task()

        async def _run():
            try:
                await self._trigger_llm_core(buffer)
            except Exception as e:
                self._dbg(f"completion error: {e!r}")

        self._llm_task = asyncio.create_task(_run())

    async def _trigger_llm_core(self, buffer) -> None:
        """Query Ollama and push the suggestion into the buffer.

        This replaces the upstream implementation that uses
        ``jupyter_ai.completions.models.InlineCompletionRequest``.  We call
        Ollama's ``/api/chat`` endpoint directly and set
        ``buffer.suggestion`` + ``buffer.on_suggestion_set.fire()`` — the
        same mechanism the upstream code uses to render ghost text.
        """
        from prompt_toolkit.auto_suggest import Suggestion

        doc = buffer.document
        line = doc.text_before_cursor.split("\n")[-1]
        # Whole-buffer context: everything the operator typed up to the
        # cursor, truncated to the tail.  Earlier lines carry the variables
        # (sess handle, target host, discovered creds) that the suggestion
        # should reference instead of inventing placeholders.
        before_cursor = doc.text_before_cursor[-_COMPLETION_MAX_CONTEXT_CHARS:]
        # Text AFTER the cursor — the closing brackets, dedent, following
        # lines that tell the model what construct it's inside.  Without
        # this, the model doesn't know it's completing inside ``payloads = [``
        # because it can't see the ``]`` that follows.
        after_cursor = doc.text_after_cursor[:_COMPLETION_MAX_AFTER_CHARS]

        # Build a FIM-style (fill-in-the-middle) context: prefix + cursor
        # marker + suffix.  Coder models (qwen2.5-coder, deepseek-coder, etc.)
        # are trained on this pattern.  Non-coder models still benefit —
        # the marker makes the continuation point unambiguous.
        if after_cursor.strip():
            typed_context = (
                before_cursor
                + _COMPLETION_CURSOR_MARKER
                + after_cursor
            )
        else:
            # Nothing after the cursor — plain continuation, no marker needed.
            typed_context = before_cursor

        # Gate: require a minimum prefix to avoid firing on a fresh prompt.
        # BUT — when the cursor is on a short/blank line inside a multi-line
        # construct (e.g. inside ``payloads = [`` ... ``]`` with a blank
        # line between items), the *current line* is empty while the *cell*
        # has plenty of context.  In that case, gate on the whole-buffer
        # length instead of the current-line length.
        if len(line) < _COMPLETION_MIN_PREFIX:
            if len(typed_context.strip()) >= _COMPLETION_MIN_PREFIX:
                # On a blank line inside a multi-line cell — query anyway.
                # The model continues from the cursor position, which may
                # be a fresh line inside a list/dict/function body.
                self._dbg(
                    f"line short ({len(line)} chars) but buffer has "
                    f"{len(typed_context.strip())} chars — querying with cell context"
                )
            else:
                self._dbg(f"line too short ({len(line)} chars) and buffer empty, skipping")
                return

        # Live namespace signal: the operator's variables + tool callables,
        # so the model knows `sess = "ssh:..."` exists to be reused.
        ns_hint = ""
        shell = self._shell
        if shell is not None:
            try:
                hints = []
                for name, val in shell.user_ns.items():
                    if name.startswith("_") or name in self._system or not isinstance(val, (str, int, float, bool, list, dict)):
                        continue
                    if callable(val):
                        continue
                    preview = repr(val)[:60]
                    hints.append(f"{name} = {preview}")
                if hints:
                    ns_hint = "Operator's live variables: " + "; ".join(hints[:12]) + ". "
            except Exception:
                pass

        self._request_number += 1
        request_number = self._request_number

        self._dbg(
            f"querying {self._model!r} | before={before_cursor[-60:]!r} "
            f"| after={after_cursor[:40]!r}"
        )
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    _ollama_query_sync,
                    self._model,
                    ns_hint + self._system,
                    typed_context,
                    self._url,
                    self._timeout_s,
                    _COMPLETION_NUM_PREDICT,
                ),
                timeout=self._timeout_s + 2,
            )
        except asyncio.TimeoutError:
            self._dbg(f"timeout after {self._timeout_s:.0f}s — model cold or busy")
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._dbg(f"query error: {exc!r}")
            return

        # Stale check — if a newer request was triggered, discard this one
        if self._request_number != request_number:
            self._dbg("stale response discarded (newer request took over)")
            return

        if result is None:
            self._dbg("no usable reply: unreachable, empty, all-<think>, or unfenced noise")
            return

        self._dbg(f"raw reply: {result[:120]!r}")

        # Trim the model reply: strip any echoed before-cursor prefix,
        # strip the typed current-line prefix, strip any echoed after-cursor
        # suffix, strip markdown fences.
        trimmed = _trim_completion(result, typed_prefix=line,
                                   after_cursor=after_cursor,
                                   before_cursor=before_cursor)
        if not trimmed:
            self._dbg(f"completion fully overlapped the typed text — nothing to show ({result[:80]!r})")
            return

        # Only set if the buffer hasn't changed since we started
        if buffer.document == doc:
            self._dbg(f"suggesting: {trimmed!r}")
            buffer.suggestion = Suggestion(trimmed)
            buffer.on_suggestion_set.fire()
        else:
            self._dbg("buffer changed during query — discarding")


def _make_ollama_suggester(
    tool_aliases: List[str],
    tool_specs: Optional[Dict[str, Dict[str, Any]]] = None,
):
    """Build an ``OllamaNavigableSuggest`` if enabled, else ``None``."""
    if not _COMPLETION_ENABLED or not _HAS_NAV_SUGGEST:
        return None
    try:
        return OllamaNavigableSuggest(tool_aliases, tool_specs=tool_specs)
    except Exception:
        return None


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
  ipython                Drop into IPython with tools as named async callables
                         (Tab-completion on tool names + params, tool? introspection,
                         cell-based chaining).  await nmap(target=...), await ffuf(...), etc.
  scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]
                         Arm the packet-scope gate (send_packet refuses
                         out-of-scope destinations; operator-only, not exposed
                         to the agent). 'scope off' disarms (lab mode).
  scope status|off|add-ip <ip> [<hostname>]|rm-ip <ip>|list-ips|search <kw> [--assets]
  help                   This message
  quit / exit            Leave the REPL

Flag args are type-coerced from the tool's own manifest schema:
  --target 10.10.10.50    string (default)
  --port 22               integer (per schema)
  --verbose               bare flag → True
  --no-verbose             → False
  --limit 5                integer (per schema)

Positional args fill required params in order:
  run auxiliaries.nmap.run_nmap 10.10.10.50 "-Pn -p 22"
  (equivalent to --target 10.10.10.50 --options "-Pn -p 22")
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
                from IPython.terminal.embed import InteractiveShellEmbed

                user_ns = build_ipython_namespace(manifests)

                tool_count = sum(1 for v in user_ns.values()
                                 if callable(v) and hasattr(v, "__manifest__"))
                print(f"  Dropping into IPython — {tool_count} tools as top-level callables.")
                print("  Tab-completes tool names + parameter keywords.")
                print("  tool?  → manifest + params    tool??  → source")
                print()
                print("  await nmap(target='10.0.0.1', options='-Pn -p 22,80')")
                print("  await ffuf(url='http://10.0.0.1', wordlist='...')")
                print("  await smb_recon(host='10.0.0.1')")
                print()
                print("  Operator functions:")
                print("    scope_on(handle, platform='h1')   scope_off()   scope_status()")
                print("    scope_search('kw', assets=True)   sessions()")
                print()
                print("  Also: tools  (dict of all wrappers),  manifests  (list),")
                print("        manifest_by_id('full.tool.id'),  run_tool,  resolve_callable")
                print()
                print("  ── UI upgrades ──")
                print(f"    Syntax highlighting: ON (colors={_IPYTHON_COLORS})")
                if _IPYTHON_TOOLBAR_ENABLED:
                    print("    Bottom toolbar: cursor L:C, cell overview + in-cell vars, globals, scope/brain")
                    print("      F1 → dump all variables (in-cell uncommitted + committed globals)")
                if _IPYTHON_RPROMPT_ENABLED:
                    print("    Right prompt: missing required params shown inside tool()")
                if _IPYTHON_MOUSE_SUPPORT:
                    print("    Mouse: click to position cursor (Shift+drag to select text)")

                # Build the Ollama suggester BEFORE the print block that
                # references it.  The suggester is a
                # ``NavigableAutoSuggestFromHistory`` subclass — IPython's
                # own on-demand LLM suggestion API (provisional in 8.32+).
                # History matching works automatically (instant ghost text
                # from past commands).  The trigger key fires an Ollama-powered
                # completion that knows about framework tool names and
                # signatures.  No prompt freezing because the LLM completion
                # is on-demand, not per-keystroke.
                tool_alias_names = sorted(
                    k for k, v in user_ns.items()
                    if callable(v) and hasattr(v, "__manifest__")
                )
                tool_specs = {
                    k: getattr(v, "__manifest__").parameters
                    for k, v in user_ns.items()
                    if callable(v) and hasattr(v, "__manifest__")
                }
                suggester = _make_ollama_suggester(
                    tool_alias_names,
                    tool_specs=tool_specs,
                )

                if suggester is not None:
                    _keyname = " + ".join(
                        k.replace("c-", "Ctrl+").replace("escape", "Esc").upper()
                        for k in _trigger_key_spec()
                    )
                    print(f"  Ollama completion: {_keyname} triggers on-demand ghost text")
                    print(f"    model={_COMPLETION_MODEL}, budget={_COMPLETION_NUM_PREDICT}tok "
                          f"(multiline), timeout={_COMPLETION_TIMEOUT_MS}ms")
                    print("    Suggestions see your whole cell + live variables.")
                    print("    History ghost text is automatic; Ollama is on-demand.")
                    print("    Set OLLAMA_COMPLETION_ENABLED=0 to disable.")
                print("  check_trigger() inside IPython verifies the chord dispatch.")
                print("  Ctrl+D / exit() to return.\n")

                # IPython.embed() → prompt_toolkit → asyncio.run() crashes with
                # "cannot be called from a running event loop" when we're inside
                # asyncio.run(repl_loop(...)).  Run embed() in a separate thread
                # so it gets a clean event-loop context.  asyncio.to_thread()
                # blocks this coroutine until the user exits IPython.
                #
                # We use InteractiveShellEmbed directly so we can explicitly
                # enable ``%autoawait asyncio`` and inject the Ollama
                # suggester before the interactive loop starts.
                def _embed():
                    # colors="linux" flips Pygments syntax highlighting ON.
                    # InteractiveShellEmbed defaults to "nocolor" which
                    # disables the IPythonPTLexer's Pygments styling — the
                    # lexer is already wired into pt_app, it just has no
                    # colour style to apply.  "linux" = dark-terminal theme.
                    # Override via IPYTHON_COLORS env (linux|neutral|lightbg|
                    # nocolor|pride|gruvbox-dark).
                    shell = InteractiveShellEmbed(
                        user_ns=user_ns, header="", colors=_IPYTHON_COLORS,
                    )
                    # Merge toolbar/rprompt style overrides into the shell's
                    # Pygments style so the bottom bar and right prompt get
                    # their own colours.
                    try:
                        existing = dict(shell.highlighting_style_overrides)
                        existing.update(_ipython_toolbar_styles())
                        shell.highlighting_style_overrides = existing
                        shell.refresh_style()
                    except Exception:
                        pass

                    # Force asyncio autoawait so ``await tool(...)`` works at
                    # the top level.  IPython rewrites the cell into an async
                    # function and runs it on its own event loop (created in
                    # this thread, which has no running loop — exactly what we
                    # need since the main loop is in the other thread).
                    shell.loop_manager = "asyncio"
                    shell.enable_gui("asyncio")
                    # Inject the Ollama suggester.  Using
                    # ``_set_autosuggestions`` is IPython's own wiring path —
                    # it sets ``shell.auto_suggest`` and syncs to ``pt_app``
                    # when it exists.  We pass "NavigableAutoSuggestFromHistory"
                    # to trigger IPython's setup (connect/disconnect handlers,
                    # key bindings), then swap in our subclass.
                    if suggester is not None:
                        suggester._shell = shell
                        shell.autosuggestions_provider = "NavigableAutoSuggestFromHistory"
                        shell._set_autosuggestions()
                        # Swap IPython's instance for our Ollama-aware subclass
                        shell.auto_suggest = suggester  # type: ignore[assignment]
                        if shell.pt_app is not None:
                            shell.pt_app.auto_suggest = suggester  # type: ignore[assignment]

                        # Bind Ctrl+O to IPython's built-in
                        # ``llm_autosuggestion`` command (bound to the trigger key), which calls
                        # ``provider._trigger_llm(event.current_buffer)``.
                        # We add it via ``shell.shortcuts`` — IPython's
                        # intended extension point for keybinding
                        # registration.  The command is in
                        # ``UNASSIGNED_ALLOWED_COMMANDS`` (no default key),
                        # so ``create=True`` adds a new binding without
                        # displacing existing ones.
                        from IPython.terminal.shortcuts.auto_suggest import (
                            llm_autosuggestion as _llm_cmd,
                        )
                        shell.shortcuts = list(shell.shortcuts) + [{
                            "command": "IPython:auto_suggest.llm_autosuggestion",
                            "new_keys": _trigger_key_spec(),
                            "create": True,
                        }]

                    # ── Bottom toolbar + rprompt + F1 globals overlay ────
                    # Wired after the shell is fully constructed (pt_app
                    # exists).  The toolbar re-renders every keystroke;
                    # the rprompt shows remaining required tool params when
                    # the cursor is inside a tool call; F1 dumps all user
                    # globals above the active prompt.
                    try:
                        _install_toolbar_and_keybindings(shell)
                    except Exception as _e:
                        if _COMPLETION_ENABLED:  # borrow the debug flag
                            print(f"[toolbar] install skipped: {_e!r}")

                    shell()

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
