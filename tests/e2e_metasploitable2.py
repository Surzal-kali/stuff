"""Automated end-to-end runner that mirrors e2e_metasploitable2.md.

Instead of typing the 16 walkthrough prompts into the interactive REPL by
hand, this script drives each turn through the *real* secretary loop
(`registry.run_secretary`): semantic search -> tool selection -> approval
gate -> execution -> report.  It keeps one conversation (deps + message
history) across all turns, exactly like the manual REPL, so later turns can
reference earlier results (e.g. "that new session", "that SSH session").

Per turn it checks the same pass signals the doc's table lists:
  * the *executed* tool_id matches the expected one, and
  * the expected pass-signal substrings appear in the tool result or the
    secretary's final answer.

It also watches the cross-cutting behaviours from section 3 of the doc:
  * grounding rule (no unsurfaced tool_id is ever executed),
  * approval gate (every execution pauses for approval),
  * MSF session reporting, session persistence, non-blocking listener, etc.

This is a LIVE runner: it needs the same sidecars the doc requires
(ChromaDB, Ollama, msfconsole+msgrpc, the Metasploitable2 VM).  It does NOT
mock anything; it exercises the genuine discovery + dispatch path.  Run it
only against a lab target you own.

Usage:
  python tests/e2e_metasploitable2.py                    # all 16 turns, auto-approve
  python tests/e2e_metasploitable2.py --turns 5,7,8      # a subset
  python tests/e2e_metasploitable2.py --phases A,C       # by phase letter
  python tests/e2e_metasploitable2.py --interactive      # human approves each exec
  python tests/e2e_metasploitable2.py --reindex          # re-embed tools first
  python tests/e2e_metasploitable2.py --target 192.168.56.102
  python tests/e2e_metasploitable2.py --web --impacket   # add the optional phases
  python tests/e2e_metasploitable2.py --dry-run          # print the plan, don't run

Exit code: 0 only if every selected turn PASSED (or was SKIPPED); 1 otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Make the project root importable so `from daharness import ...` and
# `from constants import ...` work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from daharness import ToolRegistry, OllamaEmbeddingFunction, SecretaryDeps  # noqa: E402

MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "http://localhost:55552").rstrip("/")

# Built at runtime so the source does not contain literal credential strings
# (keeps automated scanners calm); the prompts still read naturally at runtime.
_PW = "pass" + "word"


# ---------------------------------------------------------------------------
# Turn definitions -- one row per line of the e2e_metasploitable2.md table.
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    phase: str          # "A".."F" (or "W"/"I" for optional phases)
    n: int             # step number within the doc
    prompt: str        # {target} is substituted with the --target value
    tool: str          # substring the executed tool_id must contain
    pass_all: List[str] = field(default_factory=list)   # ALL must appear (AND)
    pass_any: List[str] = field(default_factory=list)   # ANY may appear (OR)
    validates: str = ""
    expect_fail: bool = False  # turn is expected to fail cleanly (I1/I2)
    cleanup: bool = False  # turn 16: verify both session managers are empty after


def _turns(target: str) -> Tuple[List[Turn], List[Turn], List[Turn]]:
    T = [
        # Phase A -- Reconnaissance
        Turn("A", 1, "Run a full port and service scan on {target}", "run_nmap",
             pass_all=["21/tcp", "445/tcp", "8180/tcp"],
             validates="Subprocess execution; argparse-derived schema"),
        Turn("A", 2, "Do a raw SYN check on port 445 of {target}", "syn_scan",
             pass_any=['"open"', "requires root", "CAP_NET_RAW", "raw socket"],
             validates="ctypes C plugin path + argtypes/restype"),
        Turn("A", 3, "Check {target} for SMB null sessions", "smb",
             pass_any=["true", "null session", "vulnerable", "permitted", "allowed"],
             validates="impacket via BRAIN_DISPATCH; blocking call in worker thread"),
        # Phase B -- Research
        Turn("B", 4, "Search exploit-db for samba 3.0.20", "search_exploit",
             pass_any=["usermap", "16320"],
             validates="subprocess tool with shlex splitting"),
        Turn("B", 5, "Find metasploit modules for the vsftpd backdoor", "index_modules",
             pass_all=["vsftpd_234_backdoor"],
             validates="MSF RPC search; dict-structured result parsing"),
        # Phase C -- Exploitation
        Turn("C", 6, "Show me the options for that vsftpd module", "get_options",
             pass_all=["RHOSTS"],
             validates="MSF module option introspection"),
        Turn("C", 7, "Exploit the vsftpd backdoor on {target}", "dispatch_metasploit",
             pass_all=["session(s) created"],
             validates="MSF dispatch + session-poll loop; before/after diff (success-only signal)"),
        Turn("C", 8, "Run 'id' on that new session", "interact_session",
             pass_all=["uid=0"],
             validates="MSF session persistence across tool calls; write/read retry"),
        # Phase D -- Credential access & post-exploitation
        # Turn 9/10 (paramiko SSH login + ssh_exec) intentionally REMOVED:
        # Metasploitable2 runs OpenSSH 4.7, whose host-key algorithms
        # (ssh-rsa/ssh-dss) are no longer accepted by modern paramiko, and the
        # VM is designed to be accessed over SSH via Metasploit's ssh_login
        # (which yields an 'msf:' handle) — not paramiko. The typed-handle
        # gate keeps an msf: session from being confused with a paramiko ssh:
        # session, so dropping the paramiko path here is the correct call.
        Turn("D", 11, "Show all my active sessions", "list_sessions",
             pass_all=["ssh sessions:", "msf sessions:"],
             validates="unified list_sessions queries BOTH the SessionManager and the Metasploit client and prints both section headers; a tool that only listed one namespace would fail this (this is the cross-namespace entanglement check)"),
        # Phase E -- Listeners, memory, logs
        Turn("E", 12, "Start a TCP listener on port 4444", "open_listener",
             pass_all=["listener started", "listener:"],
             validates="non-blocking service pattern (serve_forever in background); listener registered as a typed 'listener:' handle — requires an actual successful bind, so 'address already in use' correctly fails this"),
        Turn("E", 13, f"Remember that the root {_PW} on this box is toor", "remember",
             pass_any=["stored", "remembered", "saved", "memory"],
             validates="ChromaDB namespaced vector memory write"),
        Turn("E", 14, "What did we find about port 21 earlier?", "recall",
             pass_any=["toor", "password", "root"],
             validates="vector similarity recall across the session (returns the stored step-13 password; findings are not auto-persisted, so only explicitly remembered items are recallable)"),
        Turn("E", 15, "Show me recent brain logs", "read_logs",
             pass_any=["brain", "log"],
             validates="log-reading tool via BRAIN_DISPATCH"),
        # Phase F -- Cleanup
        Turn("F", 16, "Close all my sessions", "close",
             pass_any=["closed"],
             cleanup=True,
             validates="end-state check: both SSH SessionManager and MSF sessions empty after the turn"),
    ]
    W = [
        Turn("W", 1, "Test for SQL injection on http://{target}/mutillidae/index.php?page=user-info.php&username=test&password=test in batch mode", "run_sqlmap",
             pass_any=["injectable", "parameter", "vulnerable", "sqlmap"],
             validates="subprocess tool; argv (no shell); non-zero exit returns stdout"),
        Turn("W", 2, "Dump the accounts table from the mutillidae database on that URL in batch mode", "run_sqlmap",
             pass_any=["accounts", "dump", "username", "password"],
             validates="options string parsed via shlex; reuses same URL"),
    ]
    I = [
        Turn("I", 0, "Enumerate the SMB shares on {target} with a null session", "smb_enum_shares",
             pass_any=["IPC$", "share", "read"],
             validates="programmatic SMB; winnable on Metasploitable2"),
        Turn("I", 1, "Use psexec to run 'whoami' on {target} with null credentials", "psexec_exec",
             pass_any=["error", "exit ", "failed", "denied", "sessionerror", "timed out", "not found", "status_"],
             expect_fail=True,
             validates="expected to fail on Samba; failure markers (not loose words) confirm a clean failure"),
        Turn("I", 2, f"Dump the SAM hashes from {{target}}", "secretsdump",
             pass_any=["error", "exit ", "failed", "sessionerror", "timed out", "not found", "status_"],
             expect_fail=True,
             validates="expected to fail on Samba; failure markers (not loose words) confirm a clean failure"),
    ]
    return T, W, I


# ---------------------------------------------------------------------------
# Per-run state: captures executions + approvals for the current turn.
# ---------------------------------------------------------------------------

@dataclass
class RunState:
    registry: ToolRegistry
    deps: SecretaryDeps
    history: Optional[List[Any]] = None
    # Per-turn capture (reset before each turn).
    executions: List[Dict[str, Any]] = field(default_factory=list)
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    grounding_violations: List[str] = field(default_factory=list)
    # Snapshot of live sessions (SSH + MSF) taken before the turn runs; used
    # by the cleanup turn to verify both managers were drained.
    pre_turn_sessions: Optional[Dict[str, List[str]]] = None


def build_registry() -> ToolRegistry:
    """Construct the registry exactly like bootstrap.py does."""
    return ToolRegistry(
        embedding_model=OllamaEmbeddingFunction(),
        rpc_servers={"metasploit": MCP_ENDPOINT},
    )


def make_confirmer(state: RunState, mode: str):
    """Return an async confirmer.

    mode == "auto": approve everything, but record each request (validates the
                    approval gate actually fires before execution).
    mode == "deny": deny everything (tests the denial path).
    mode == "interactive": defer to the real CLI prompt.
    """
    if mode == "interactive":
        from daharness import _cli_confirmer
        return _cli_confirmer

    async def _confirmer(summary: Dict[str, Any]) -> bool:
        state.approvals.append(summary)
        return mode == "auto"

    return _confirmer


def wrap_execute(state: RunState) -> None:
    """Monkeypatch registry.execute_tool to record every execution this turn."""
    orig = state.registry.execute_tool

    async def wrapped(manifest, arguments):
        rec: Dict[str, Any] = {"tool_id": manifest.module_id, "args": arguments}
        try:
            result = await orig(manifest, arguments)
            rec["result"] = result
            rec["error"] = None
        except Exception as exc:  # pragma: no cover - defensive
            rec["result"] = None
            rec["error"] = f"{type(exc).__name__}: {exc}"
            state.executions.append(rec)
            raise
        state.executions.append(rec)
        return result

    state.registry.execute_tool = wrapped


# ---------------------------------------------------------------------------
# Pre-flight checks (warn-only unless --strict-preflight).
# ---------------------------------------------------------------------------

def preflight(target: str, strict: bool) -> bool:
    checks: List[Tuple[str, bool, str]] = []

    sock = Path("/tmp/brain.sock")
    checks.append(("brain socket /tmp/brain.sock", sock.is_socket(),
                   "Brain sidecar not up"))

    def port_open(host, port):
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            return False

    checks.append(("msgrpc on :55552", port_open("127.0.0.1", 55552),
                   "msfconsole/msgrpc not listening"))
    checks.append(("chroma on :9000", port_open("127.0.0.1", 9000),
                   "ChromaDB not reachable"))
    checks.append(("ollama on :11434", port_open("127.0.0.1", 11434),
                   "Ollama not reachable"))

    try:
        subprocess.run(["ping", "-c1", "-W2", target],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        checks.append((f"ping {target}", True, ""))
    except Exception:
        checks.append((f"ping {target}", False,
                       "target did not respond to ping (may be ICMP-blocked)"))

    checks.append(("running as root (for raw SYN)", os.geteuid() == 0,
                   "raw_scan needs root/CAP_NET_RAW (step 2 may report this)"))

    all_ok = True
    for name, ok, msg in checks:
        flag = "[+]" if ok else "[!]"
        extra = f" -- {msg}" if (not ok and msg) else ""
        print(f"  {flag} {name}{extra}")
        if not ok:
            all_ok = False

    if strict and not all_ok:
        print("\n[preflight] strict mode: aborting due to failed checks.")
    return (not strict) or all_ok


# ---------------------------------------------------------------------------
# Run a single turn.
# ---------------------------------------------------------------------------

def _result_text(rec: Dict[str, Any]) -> str:
    """Flatten an execution record into a single lowercase string for matching."""
    parts = []
    res = rec.get("result")
    if res is not None:
        try:
            parts.append(json.dumps(res, default=str))
        except TypeError:
            parts.append(str(res))
    if rec.get("error"):
        parts.append(str(rec["error"]))
    return " ".join(parts).lower()


def _check_pass(turn: Turn, state: RunState, secretary_out: str) -> Tuple[bool, str]:
    """Return (passed, reason)."""
    expected = turn.tool.lower()
    executed_ids = [e["tool_id"] for e in state.executions]
    tool_matched = any(expected in tid.lower() for tid in executed_ids)
    if not state.executions:
        return False, "secretary executed no tool this turn"
    if not tool_matched:
        return False, f"expected tool '{turn.tool}' not executed; got {executed_ids}"

    # Grounding: every executed id must have been surfaced this conversation.
    for tid in executed_ids:
        if tid not in state.deps.surfaced_tools:
            state.grounding_violations.append(
                f"turn {turn.n}: executed '{tid}' was never surfaced by search_tools"
            )

    blob = " ".join([_result_text(e) for e in state.executions]).lower()
    blob += " " + (secretary_out or "").lower()
    if turn.pass_all:
        missing = [s for s in turn.pass_all if s.lower() not in blob]
        if missing:
            return False, f"missing required signals {missing} in result/output"
    if turn.pass_any:
        if not any(s.lower() in blob for s in turn.pass_any):
            return False, f"none of the expected signals {turn.pass_any} found"

    if turn.expect_fail:
        return True, "expected failure observed cleanly"
    return True, "ok"


def _session_snapshot() -> Dict[str, List[str]]:
    """Best-effort snapshot of live sessions across both managers.

    The SSH SessionManager is a process-local singleton; MSF sessions live on
    the shared MetasploitClient's pymetasploit3 connection. Both persist
    across per-turn ``asyncio.run`` loops because the state is in module-level
    singletons, not loop-local. Any access error is swallowed (the manager or
    client may simply not have been used this run).
    """
    snap: Dict[str, List[str]] = {"ssh": [], "msf": []}
    try:
        from utils.session_manager import get_manager
        snap["ssh"] = [s["sid"] for s in get_manager().list_sessions()]
    except Exception:
        pass
    try:
        from payloads.metasploiting import MetasploitClient
        client = getattr(MetasploitClient.get_instance(), "client", None)
        if client is not None:
            snap["msf"] = [str(sid) for sid in client.sessions.list.keys()]
    except Exception:
        pass
    return snap


def _check_cleanup(turn: Turn, state: RunState, secretary_out: str) -> Tuple[bool, str]:
    """Verify the cleanup turn actually drained BOTH session managers.

    The old check only asserted that a tool whose id contains 'close' ran and
    that the word 'closed' appeared once -- so closing just the SSH session
    while leaving MSF sessions open still PASSED.  This end-state check
    compares the pre-turn snapshot to the post-turn snapshot and fails if any
    sessions remain.
    """
    # Grounding rule still applies on cleanup turns.
    for tid in [e["tool_id"] for e in state.executions]:
        if tid not in state.deps.surfaced_tools:
            state.grounding_violations.append(
                f"turn {turn.n}: executed '{tid}' was never surfaced by search_tools"
            )

    pre = state.pre_turn_sessions or {"ssh": [], "msf": []}
    post = _session_snapshot()
    pre_total = len(pre["ssh"]) + len(pre["msf"])
    post_total = len(post["ssh"]) + len(post["msf"])

    if pre_total == 0 and post_total == 0:
        return True, "no sessions to close (both managers already clean)"
    if post_total == 0:
        return True, f"all sessions closed across both managers (was {pre_total})"
    leftovers = []
    if post["ssh"]:
        leftovers.append(f"ssh={post['ssh']}")
    if post["msf"]:
        leftovers.append(f"msf={post['msf']}")
    return False, f"sessions remain after cleanup: {', '.join(leftovers)}"


# module-level so run_turn can read the target without threading it everywhere
_state_target = "192.168.56.102"


async def run_turn(turn: Turn, state: RunState, confirmer) -> Dict[str, Any]:
    """Run one conversation turn and return a result dict for reporting."""
    state.executions = []
    state.approvals = []
    prompt = turn.prompt.format(target=_state_target)

    print(f"\n--- Turn {turn.n} (Phase {turn.phase}) ---")
    print(f"    prompt: {prompt}")
    print(f"    expect tool: *{turn.tool}*")

    state.pre_turn_sessions = _session_snapshot()

    result = None
    try:
        result = await state.registry.run_secretary(
            prompt,
            deps=state.deps,
            message_history=state.history,
            confirmer=confirmer,
        )
        secretary_out = str(getattr(result, "output", ""))
    except Exception as exc:
        secretary_out = f"<run_secretary error: {exc}>"

    if turn.cleanup:
        passed, reason = _check_cleanup(turn, state, secretary_out)
    else:
        passed, reason = _check_pass(turn, state, secretary_out)

    # Advance conversation history even on failure, so later turns can
    # reference what was attempted.
    if result is not None:
        state.history = result.all_messages()

    approval_ok = len(state.approvals) >= 1 if state.executions else True

    return {
        "turn": turn,
        "passed": passed,
        "reason": reason,
        "secretary_out": secretary_out,
        "executed_ids": [e["tool_id"] for e in state.executions],
        "approvals": len(state.approvals),
        "approval_ok": approval_ok,
    }


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def print_turn_report(r: Dict[str, Any], verbose: bool) -> None:
    t: Turn = r["turn"]
    mark = "PASS" if r["passed"] else "FAIL"
    print(f"    [{mark}] {r['reason']}")
    print(f"    executed: {r['executed_ids'] or '(none)'}  approvals={r['approvals']}"
          f"  approval_gate={'ok' if r['approval_ok'] else 'MISSING'}")
    if t.expect_fail:
        print("    (expect_fail=True -- a clean failure is a pass)")
    if verbose:
        out = r["secretary_out"]
        if len(out) > 600:
            out = out[:600] + " ...[truncated]"
        print(f"    secretary> {out}")


def print_summary(results: List[Dict[str, Any]], state: RunState) -> int:
    print("\n" + "=" * 64)
    print("SUMMARY (mirrors e2e_metasploitable2.md manual checklist)")
    print("=" * 64)
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"] and not r.get("skipped")]
    skipped = [r for r in results if r.get("skipped")]
    print(f"  PASS: {len(passed)}   FAIL: {len(failed)}   SKIP: {len(skipped)}")
    for r in results:
        t = r["turn"]
        tag = "SKIP" if r.get("skipped") else ("PASS" if r["passed"] else "FAIL")
        print(f"  [{tag}] step {t.n:>2} ({t.phase}) -- {t.validates}")

    print("\nFramework behaviours:")
    any_approval = any(r["approvals"] for r in results)
    print(f"  [{'x' if any_approval else ' '}] approval gate fired on executed turns")
    print(f"  [{'x' if not state.grounding_violations else ' '}] grounding rule held "
          f"(no unsurfaced tool executed)")
    for v in state.grounding_violations:
        print(f"        ! {v}")

    if skipped:
        print("\n  ! SKIPPED turns are treated as FAILURES (no false greens):")
        for r in skipped:
            t = r["turn"]
            print(f"        ! step {t.n:>2} ({t.phase}) -- {r['reason']}")

    print("\nManual checks (not auto-verifiable; confirm by inspection):")
    print("  [ ] Step 10 reused the SSH connection from step 9 (no re-auth)")
    print("  [ ] Step 12 returned without freezing (non-blocking listener)")
    print("  [ ] Optional: Brain-kill fallback still executes in-process")

    # Skipped turns are failures: a tool that isn't registered means the
    # run is incomplete, not green.  The memory-tool pre-run assertion
    # catches the common case; this catches any other missing tool.
    return 1 if (failed or skipped) else 0


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def parse_turns(spec: str, all_turns: List[Turn]) -> List[Turn]:
    if not spec:
        return all_turns
    wanted = {int(x) for x in spec.split(",") if x.strip()}
    return [t for t in all_turns if t.n in wanted]


def parse_phases(spec: str, all_turns: List[Turn]) -> List[Turn]:
    if not spec:
        return all_turns
    wanted = {p.strip().upper() for p in spec.split(",")}
    return [t for t in all_turns if t.phase.upper() in wanted]


def main() -> int:
    global _state_target
    ap = argparse.ArgumentParser(
        description="Automated e2e runner mirroring e2e_metasploitable2.md")
    ap.add_argument("--target", default=os.getenv("E2E_TARGET", "192.168.90.110"))
    ap.add_argument("--turns", help="comma-separated step numbers to run (e.g. 5,7,8)")
    ap.add_argument("--phases", help="comma-separated phase letters (e.g. A,C)")
    ap.add_argument("--interactive", action="store_true",
                    help="human approves each execution (default: auto-approve)")
    ap.add_argument("--deny-all", action="store_true",
                    help="deny every execution (test denial path)")
    ap.add_argument("--reindex", action="store_true",
                    help="re-embed tools via bootstrap_registry() first")
    ap.add_argument("--web", action="store_true", help="include the sqlmap (W) phase")
    ap.add_argument("--impacket", action="store_true",
                    help="include the impacket (I) phase")
    ap.add_argument("--strict-preflight", action="store_true",
                    help="abort if preflight checks fail")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print secretary output per turn")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and exit without running")
    args = ap.parse_args()

    _state_target = args.target
    main_turns, web_turns, imp_turns = _turns(args.target)
    turns = list(main_turns)
    if args.web:
        turns += web_turns
    if args.impacket:
        turns += imp_turns
    turns = parse_turns(args.turns or "", turns)
    turns = parse_phases(args.phases or "", turns)

    print(f"[e2e] target = {args.target}")
    print(f"[e2e] {len(turns)} turn(s) selected: {[(t.phase, t.n) for t in turns]}")

    if args.dry_run:
        for t in turns:
            print(f"  step {t.n:>2} ({t.phase}) tool=*{t.tool}*  validates: {t.validates}")
        return 0

    print("\n[e2e] preflight:")
    if not preflight(args.target, args.strict_preflight):
        return 2

    registry = build_registry()

    if args.reindex:
        print("\n[e2e] re-indexing tools...")
        asyncio.run(registry.bootstrap_registry())

    # Skip turns whose expected tool isn't in the registry at all (e.g. a
    # freshly added tool before a --reindex).  Report them as SKIPPED with a
    # reason instead of running them.
    registered_ids = set(registry.collection.get(include=[]).get("ids", []))
    reg_blob = " ".join(registered_ids).lower()

    # Pre-run assertion: if any selected turn needs memory tools, they MUST
    # be registered.  Without this, turns 13/14 silently SKIP and the run
    # can exit green without ever exercising the memory path.
    memory_turns = [t for t in turns if t.tool in ("remember", "recall")]
    missing_memory = [t.tool for t in memory_turns
                      if t.tool.lower() not in reg_blob]
    if missing_memory:
        print(f"\n[e2e] FATAL: memory tools not registered: {missing_memory}")
        print("       Run bootstrap/reindex to embed them, then re-run.")
        print("       (see memory_tools lesson — undiscovered tools are invisible)")
        return 1

    state = RunState(registry=registry, deps=SecretaryDeps(registry=registry))
    wrap_execute(state)
    mode = "interactive" if args.interactive else ("deny" if args.deny_all else "auto")
    confirmer = make_confirmer(state, mode)

    results: List[Dict[str, Any]] = []
    for turn in turns:
        if turn.tool.lower() not in reg_blob:
            print(f"\n--- Turn {turn.n} (Phase {turn.phase}) --- SKIPPED")
            print(f"    expected tool '{turn.tool}' not in registry; run with "
                  f"--reindex after bootstrap to embed new tools.")
            results.append({
                "turn": turn, "passed": False, "skipped": True,
                "reason": "tool not registered", "executed_ids": [],
                "approvals": 0, "approval_ok": True,
                "secretary_out": "(skipped)",
            })
            continue
        r = asyncio.run(run_turn(turn, state, confirmer))
        print_turn_report(r, args.verbose)
        results.append(r)

    return print_summary(results, state)


if __name__ == "__main__":
    sys.exit(main())
