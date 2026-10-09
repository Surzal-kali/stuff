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

    return ns


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

_COMPLETION_ENABLED = os.getenv("OLLAMA_COMPLETION_ENABLED", "1").lower() not in ("0", "false", "no", "off")
_COMPLETION_MODEL = (
    os.getenv("OLLAMA_COMPLETION_MODEL")
    or os.getenv("SECRETARY_MODEL")
    or "qwen2.5-coder:7b"
)
_COMPLETION_TIMEOUT_MS = int(os.getenv("OLLAMA_COMPLETION_TIMEOUT_MS", "3000"))
_COMPLETION_MIN_PREFIX = int(os.getenv("OLLAMA_COMPLETION_MIN_PREFIX", "3"))
_COMPLETION_MAX_FAILURES = 5
_COMPLETION_BACKOFF_COOLDOWN_S = 15.0
# Max tool aliases included in the completion system prompt.  190+ tools at
# ~15 chars each is ~3KB — fine for a 14B model's context window.  Set to 0
# for no limit.
_COMPLETION_MAX_TOOLS = int(os.getenv("OLLAMA_COMPLETION_MAX_TOOLS", "250"))


def _ollama_generate_url() -> str:
    """Derive the Ollama ``/api/generate`` endpoint from ``OLLAMA_BASE_URL``.

    ``OLLAMA_BASE_URL`` is the OpenAI-compatible endpoint (``.../v1``).
    Ollama's native chat API lives at ``.../api/chat`` (no ``/v1``).
    """
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    # Strip /v1 suffix if present
    if base.endswith("/v1"):
        base = base[:-3]
    return base.rstrip("/") + "/api/chat"


# Base class for the suggester — ``AutoSuggest`` if prompt_toolkit is
# installed, ``object`` otherwise (so the class definition never fails even
# if prompt_toolkit is missing; ``_make_ollama_suggester`` guards the import).
try:
    from prompt_toolkit.auto_suggest import AutoSuggest as _AutoSuggestBase
except ImportError:
    _AutoSuggestBase = object  # type: ignore[misc,assignment]


class OllamaAutoSuggest(_AutoSuggestBase):
    """prompt_toolkit ``AutoSuggest`` backed by a local Ollama model.
    
    Produces inline ghost-text completions for the IPython prompt.  The
    suggestion is context-aware: the prompt includes the available tool
    aliases and their parameter names so the model suggests real tool calls
    with correct arguments (including ``await`` for async wrappers).
    
    Falls back gracefully when Ollama is unreachable or busy — no suggestion
    is shown, and the circuit breaker prevents retry storms.
    """

    def __init__(self, tool_aliases: List[str], timeout_ms: int = _COMPLETION_TIMEOUT_MS):
        from prompt_toolkit.auto_suggest import Suggestion
        
        self._Suggestion = Suggestion
        self._tool_aliases = sorted(tool_aliases)
        self._timeout_s = timeout_ms / 1000.0
        self._url = _ollama_generate_url()
        self._model = _COMPLETION_MODEL
        
        # Circuit breaker state
        self._failures = 0
        self._cooldown_until = 0.0
        self._lock = _threading_mod.Lock()
        
        # Cold-start state: the first request to Ollama may take 5-10s while
        # the model loads into VRAM. Don't count that as a failure — give it
        # a longer timeout on the first call, and don't let early timeouts
        # open the circuit breaker.
        self._first_call = True
        self._cold_start_timeout_s = max(self._timeout_s * 3, 10.0)
        
        # Last-suggestion cache: (prefix, suggestion_text)
        self._cached_prefix: str = ""
        self._cached_suggestion: str = ""

        # Build a compact system prompt listing available tools.
        # _COMPLETION_MAX_TOOLS caps the list size (0 = no limit); 190+ tool
        # aliases at ~15 chars each is ~3KB, well within context budget.
        if _COMPLETION_MAX_TOOLS > 0:
            tools_list = ", ".join(self._tool_aliases[:_COMPLETION_MAX_TOOLS])
        else:
            tools_list = ", ".join(self._tool_aliases)
        self._system = (
            "You are a code completion engine. OUTPUT RULES: output ONLY raw "
            "Python code that continues the user's line. No explanations, no "
            "markdown, no backticks, no comments, no prose. If the user typed "
            "'await nmap(' you output 'target=...'. If you cannot complete the "
            "code, output nothing. Available async tool callables (prefix with "
            "await): " + tools_list + ". Sync functions: scope_on, scope_off, "
            "scope_status, scope_search, sessions."
        )

    def _should_attempt(self) -> bool:
        """Circuit breaker: are we allowed to try?"""
        if not _COMPLETION_ENABLED:
            return False
        with self._lock:
            if self._failures >= _COMPLETION_MAX_FAILURES:
                if time.monotonic() < self._cooldown_until:
                    return False
                # Cooldown expired — reset and try again
                self._failures = 0
                self._cooldown_until = 0.0
            return True

    def _record_success(self):
        with self._lock:
            self._failures = 0

    def _record_failure(self):
        with self._lock:
            self._failures += 1
            if self._failures >= _COMPLETION_MAX_FAILURES:
                self._cooldown_until = time.monotonic() + _COMPLETION_BACKOFF_COOLDOWN_S

    def _query_ollama(self, current_line: str) -> Optional[str]:
        """Send a completion request to Ollama.  Returns the completion text
        (what follows the cursor) or ``None`` on any failure/timeout.
        
        This is a *synchronous* HTTP call — it's always invoked from a worker
        thread (via ``get_suggestion_async``) so it never blocks the prompt
        event loop.
        """
        import urllib.request
        import urllib.error

        # Use the chat endpoint with a primed assistant turn — this is far
        # more reliable than the raw generate endpoint for chat-tuned models
        # (qwen2.5-coder, etc.) which otherwise wrap output in markdown fences
        # or produce conversational preambles. The assistant priming message
        # ("```python\n") makes the model continue inside a code block; we
        # strip the fence markers from the response.
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": self._system},
                {"role": "user", "content": current_line},
                {"role": "assistant", "content": "```python\n"},
            ],
            "stream": False,
            "options": {
                "num_predict": 40,       # short completion, not a paragraph
                "temperature": 0.2,      # deterministic-ish
                "stop": ["\n\n", "\nimport ", "\nfrom ", "\nclass ", "\ndef ", "```"],
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            # Socket timeout must be >= the async wrapper's timeout so the
            # async timeout fires first (cleaner circuit-breaker accounting).
            # Use the cold-start timeout on the first call to allow model
            # loading; subsequent calls use the normal timeout.
            sock_timeout = (self._cold_start_timeout_s if self._first_call else self._timeout_s) + 2
            with urllib.request.urlopen(req, timeout=sock_timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
            self._record_failure()
            return None

        # Chat endpoint: {"message": {"content": "..."}}.
        # The assistant was primed with "```python\n" so the model continues
        # inside a code block. Strip any fence markers and take the content.
        msg = body.get("message") or {}
        raw = (msg.get("content") or "").strip()
        if not raw:
            self._record_failure()
            return None

        # Strip markdown code fences if present (the priming already opened
        # one, but the model might re-emit it in some contexts)
        if raw.startswith("```"):
            # Remove opening fence line
            lines = raw.split("\n")
            if lines[0].strip().startswith("```"):
                lines = lines[1:]
            # Remove closing fence if present
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            raw = "\n".join(lines).strip()

        if not raw:
            self._record_failure()
            return None

        self._record_success()
        return raw

    def _trim_to_line(self, completion: str, document, typed_prefix: str = "") -> str:
        """Trim the completion to the first line and strip any echoed prefix.
        
        Chat-tuned models often regenerate the entire line (e.g. ``await
        nmap(target=...)``) even though the user already typed ``await nmap(``.
        Ghost text should show only what comes *after* the cursor, so we
        strip the typed prefix from the beginning of the completion.
        """
        # Only the first line is useful for ghost text
        completion = completion.split("\n")[0]
        # Strip trailing whitespace
        completion = completion.rstrip()
        if not completion:
            return ""
        # Strip the typed prefix if the model echoed it back
        if typed_prefix and completion.startswith(typed_prefix):
            completion = completion[len(typed_prefix):]
        # Also strip text after the cursor if the completion overlaps it
        text_after_cursor = document.text_after_cursor.split("\n")[0]
        if text_after_cursor and completion.startswith(text_after_cursor):
            completion = completion[len(text_after_cursor):]
        return completion

    def get_suggestion(self, buffer, document):
        """Synchronous path — not used by IPython (it calls the async override),
        but required by the ``AutoSuggest`` ABC.
        """
        if not self._should_attempt():
            return None

        line = document.text_before_cursor.split("\n")[-1]
        if len(line) < _COMPLETION_MIN_PREFIX:
            return None

        # Cache hit: the current line extends the cached prefix
        if self._cached_suggestion and line.startswith(self._cached_prefix) and len(line) > len(self._cached_prefix):
            remaining = line[len(self._cached_prefix):]
            if self._cached_suggestion.startswith(remaining):
                trimmed = self._cached_suggestion[len(remaining):]
                if trimmed:
                    return self._Suggestion(trimmed)

        result = self._query_ollama(line)
        if result is None:
            return None

        trimmed = self._trim_to_line(result, document, typed_prefix=line)
        if not trimmed:
            return None

        # Cache for next keystroke
        self._cached_prefix = line
        self._cached_suggestion = trimmed

        return self._Suggestion(trimmed)

    async def get_suggestion_async(self, buff, document):
        """Asynchronous path — this is what prompt_toolkit/IPython calls.
        
        Runs the synchronous Ollama query in a worker thread with a hard
        wall-clock timeout.  If the timeout fires (Ollama is busy), returns
        ``None`` (no ghost text) and records a failure for the circuit breaker.
        """
        line = document.text_before_cursor.split("\n")[-1]

        if not self._should_attempt():
            return None

        if len(line) < _COMPLETION_MIN_PREFIX:
            return None

        # Cache hit
        if self._cached_suggestion and line.startswith(self._cached_prefix) and len(line) > len(self._cached_prefix):
            remaining = line[len(self._cached_prefix):]
            if self._cached_suggestion.startswith(remaining):
                trimmed = self._cached_suggestion[len(remaining):]
                if trimmed:
                    return self._Suggestion(trimmed)

        # Use a longer timeout on the first call to allow cold model loading
        # (qwen2.5-coder:14b takes 5-6s to load into VRAM on first request).
        # After the first successful response, switch to the normal timeout.
        current_timeout = self._cold_start_timeout_s if self._first_call else self._timeout_s

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._query_ollama, line),
                timeout=current_timeout,
            )
            self._first_call = False
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # Don't count cold-start timeouts as failures — the model is just
            # loading. Only count failures after the first successful response.
            if not self._first_call:
                self._record_failure()
            return None
        except Exception as _exc:
            if not self._first_call:
                self._record_failure()
            return None

        if result is None:
            return None

        trimmed = self._trim_to_line(result, document, typed_prefix=line)
        if not trimmed:
            return None

        self._cached_prefix = line
        self._cached_suggestion = trimmed

        return self._Suggestion(trimmed)


def _make_ollama_suggester(tool_aliases: List[str]):
    """Build an ``OllamaAutoSuggest`` if enabled, else ``None``.
    
    Returns ``None`` when completions are disabled (``OLLAMA_COMPLETION_ENABLED=0``)
    or when prompt_toolkit is not installed — IPython falls back to its
    built-in history suggester.
    """
    if not _COMPLETION_ENABLED:
        return None
    try:
        return OllamaAutoSuggest(tool_aliases)
    except ImportError:
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
                if _COMPLETION_ENABLED:
                    print(f"  Ghost text: Ollama auto-suggest (model={_COMPLETION_MODEL}, "
                          f"timeout={_COMPLETION_TIMEOUT_MS}ms, backoff after "
                          f"{_COMPLETION_MAX_FAILURES} failures)")
                    print("    Set OLLAMA_COMPLETION_ENABLED=0 to disable.")
                print("  Ctrl+D / exit() to return.\n")

                # IPython.embed() → prompt_toolkit → asyncio.run() crashes with
                # "cannot be called from a running event loop" when we're inside
                # asyncio.run(repl_loop(...)).  Run embed() in a separate thread
                # so it gets a clean event-loop context.  asyncio.to_thread()
                # blocks this coroutine until the user exits IPython.
                #
                # We use InteractiveShellEmbed directly (instead of the bare
                # ``embed()`` convenience) so we can explicitly enable
                # ``%autoawait asyncio`` before the interactive loop starts.
                # Without this, ``await nmap(...)`` at the top level can fail
                # with "SyntaxError: await outside function" — embed() in a
                # separate thread doesn't always inherit the default autoawait
                # policy, depending on IPython version.
                #
                # We also inject an ``OllamaAutoSuggest`` (ghost-text inline
                # completions) onto the shell after it initializes its
                # prompt_toolkit app — the ``pt_app`` attribute holds the
                # ``PromptSession``, and setting ``auto_suggest`` there wires
                # our suggester into the prompt's rendering loop.
                tool_alias_names = sorted(
                    k for k, v in user_ns.items()
                    if callable(v) and hasattr(v, "__manifest__")
                )
                suggester = _make_ollama_suggester(tool_alias_names)

                def _embed():
                    shell = InteractiveShellEmbed(user_ns=user_ns, header="")
                    # Force asyncio autoawait so ``await tool(...)`` works at
                    # the top level.  IPython rewrites the cell into an async
                    # function and runs it on its own event loop (created in
                    # this thread, which has no running loop — exactly what we
                    # need since the main loop is in the other thread).
                    shell.loop_manager = "asyncio"
                    shell.enable_gui("asyncio")
                    # Inject the Ollama ghost-text suggester.
                    #
                    # IPython's ``_extra_prompt_options()`` builds the kwargs
                    # dict passed to ``pt_app.prompt()``.  Critically, it does
                    # NOT include ``auto_suggest`` — prompt_toolkit's
                    # ``PromptSession.prompt()`` only activates auto-suggest
                    # when the ``auto_suggest`` parameter is explicitly passed
                    # to ``prompt()``, NOT when ``self.auto_suggest`` is set
                    # on the session.  Setting ``shell.auto_suggest`` or
                    # ``shell.pt_app.auto_suggest`` alone has no effect.
                    #
                    # The fix: wrap ``_extra_prompt_options`` to inject
                    # ``auto_suggest`` into the returned dict.  This is the
                    # single point where the suggester flows into the actual
                    # prompt rendering loop.
                    if suggester is not None:
                        shell.auto_suggest = suggester  # type: ignore[assignment]
                        _orig_opts = shell._extra_prompt_options
                        _suggester_ref = suggester  # capture for closure
                        def _opts_with_suggest(*a, **kw):
                            opts = _orig_opts(*a, **kw)
                            opts["auto_suggest"] = _suggester_ref
                            return opts
                        shell._extra_prompt_options = _opts_with_suggest  # type: ignore[assignment]
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
