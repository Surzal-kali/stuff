"""Radare2 static-analysis composite tool (``run_r2``).

A single ``@framework_tool`` that drives radare2 as a one-shot subprocess
for static binary analysis: disassembly, decompilation (r2ghidra), symbol /
import / export / section / string enumeration, and cross-reference
queries.  There is deliberately ONE tool, not one per r2 command — the
secretary model picks the verb from a frozen allowlist and the tool composes
a safe ``-c`` string itself.

Threat model & validation (defense in depth)
--------------------------------------------
The injection surface is r2 itself, not bash: radare2's ``-c`` parser splits
on ``;`` and newlines, so a crafted ``addr`` could chain a second r2
command.  We defeat this with four independent layers:

1. **Exact allowlist match** on ``command`` — only the 19 frozen verbs are
   accepted (20th slot reserved).  No substring, no prefix match.
2. **Forbidden-character scan** on every free-text input (``command``,
   ``addr``): rejects `` ! ` $ > | & ; " '`` and newline.  These are the
   characters that matter to r2's ``-c`` parser and to a shell.
3. **Strict addr charset** — ``addr`` must be either a hex integer
   (``0x[0-9a-fA-F]+``) or a flag/symbol name (``[A-Za-z0-9_.$-]+``).  The
   tool composes ``cmd @ <addr>`` itself; the ``@`` never travels as free
   text from the caller.
4. **Integer caps** — ``count`` is coerced to int and clamped (``pd`` ≤ 512
   instructions, ``px`` ≤ 1024 bytes) so a fat binary can't be made to dump
   unbounded output.

The tool invokes r2 via a subprocess **argv list** (``shell=False``), so even
if a forbidden char slipped through it would never reach a shell.  r2 runs
against a **per-run temp copy** of the target binary and is never opened with
``-w``, so the original file is read-only by construction — the temp copy is
the only thing r2 could ever touch, and it is unlinked in ``finally``.

One-shot shape
--------------
::

    r2 -q -e scr.color=0 -e scr.utf8=0 -c 'aaa; <cmd> [<count>] [@ <addr>]' <tmpcopy>

A fresh r2 process is spawned per call: no session state, no seek/write
persistence between calls.  ``aaa`` (full analysis) is always prepended as
the opener so symbol-dependent commands (``afl``, ``pdf``, ``axt`` …) work
without the model having to chain a separate analysis call across a
stateless boundary.

Preflight
---------
``pdg`` (r2ghidra decompile) is the value item but depends on an optional
plugin.  A module-level cached probe checks for r2ghidra once per process;
if it is missing, a ``pdg`` call returns a clean envelope —
``"r2ghidra not installed — run: r2pm -ci r2ghidra"`` — instead of a raw
traceback.  Every other command works without the plugin.

Truncation
----------
``izz`` (whole-file strings) and ``afl`` (function list) explode on
fat/static binaries.  Output is capped at ``R2_OUTPUT_CAP`` bytes (default
200 KiB) with a stated policy in the envelope so the model knows it is
seeing a prefix, not the full result.

Binary drop folder
------------------
Analysis targets live in a dedicated, gitignored ``binaries/`` directory at
the repo root (override via ``R2_BINARY_TARGETS_ROOT`` env).  Drop an ELF,
PE, Mach-O, shared lib, or object file there and the model can discover it
with ``list_r2_targets`` and then call ``run_r2`` with just the bare name
— ``run_r2`` auto-resolves a non-path ``target`` against the drop folder so
the model never needs to know the full filesystem path.  The folder itself
is walked recursively and filtered to files with recognised binary magic
bytes so text files and junk don't pollute the listing.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool


# ---------------------------------------------------------------------------
# Frozen command table — schema-verified against radare2 6.2.1 on production.
# 19 slots filled; the 20th is held open for a practice-found gap.
# Each entry: verb -> (needs_addr, needs_count, count_cap, blurb)
# ---------------------------------------------------------------------------
_COMMAND_TABLE: Dict[str, Tuple[bool, bool, int, str]] = {
    # --- analysis / function discovery ---
    "aaa": (False, False, 0, "full analysis (always prepended as opener)"),
    "afl": (False, False, 0, "list discovered functions"),
    "af":  (True,  False, 0, "targeted function analysis at addr"),
    "afi": (True,  False, 0, "function info: addr/size/bbs/args"),
    # --- binary metadata ---
    "iI":  (False, False, 0, "binary info: arch, format, PIE/canary/NX"),
    "iS":  (False, False, 0, "sections"),
    "iE":  (False, False, 0, "exports"),
    "ii":  (False, False, 0, "imports"),
    "is":  (False, False, 0, "symbols"),
    "iR":  (False, False, 0, "relocations / ASLR"),
    # --- strings ---
    "iz":  (False, False, 0, "strings in data sections"),
    "izz": (False, False, 0, "strings across whole file (creds/paths/URLs)"),
    # --- disassembly / decompilation ---
    "pdf": (True,  False, 0, "disassemble function at addr (workhorse)"),
    "pdg": (True,  False, 0, "r2ghidra decompile at addr (no asm fluency needed)"),
    "pd":  (True,  True,  512, "fixed-N disassembly at addr"),
    "px":  (True,  True,  1024, "hexdump at addr"),
    # --- cross-references ---
    "axt": (True,  False, 0, "xrefs TO addr (what calls/references this)"),
    "axf": (True,  False, 0, "xrefs FROM addr (what this calls/references)"),
    # --- string-at-addr ---
    "ps":  (True,  False, 0, "print string at addr (pairs with axt-on-strings)"),
    # slot 20: reserved for a practice-found gap
}

ALLOWED_COMMANDS: Tuple[str, ...] = tuple(_COMMAND_TABLE.keys())

# Commands that require r2ghidra (checked via preflight).
_R2GHIDRA_COMMANDS: Tuple[str, ...] = ("pdg",)

# Forbidden characters — the r2 -c parser splits on ';' and newline; the rest
# are shell-significant chars we reject as defense in depth even though we
# never use shell=True.
_FORBIDDEN_CHARS: Tuple[str, ...] = (" ", "!", "`", "$", ">", "|", "&",
                                      ";", '"', "'", "\n")
_FORBIDDEN_RE: re.Pattern = re.compile(
    r"[\s!`$>|&;\"'\n]"
)

# Strict addr charset: hex integer OR flag/symbol name.
_ADDR_HEX_RE: re.Pattern = re.compile(r"^0x[0-9a-fA-F]+$")
_ADDR_FLAG_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_.$\-]+$")

# Output truncation cap (bytes).  Tunable via env so fat-binary runs can be
# widened without a code change.
_OUTPUT_CAP: int = int(os.getenv("R2_OUTPUT_CAP", str(200 * 1024)))
_TRUNCATION_NOTE: str = (
    f"output capped at {_OUTPUT_CAP} bytes (R2_OUTPUT_CAP env) — "
    "this is a prefix, not the full result; narrow with addr/count or "
    "use a more targeted command"
)

# r2 subprocess timeout (seconds).  aaa on a fat static binary can be slow.
_R2_TIMEOUT: float = float(os.getenv("R2_TIMEOUT", "120"))


# ---------------------------------------------------------------------------
# Binary drop folder — discovery & resolution
# ---------------------------------------------------------------------------
# A dedicated, gitignored directory for analysis targets.  The model drops
# (or finds) binaries here, lists them with ``list_r2_targets``, and calls
# ``run_r2`` with the bare name — ``run_r2`` auto-resolves via
# :func:`resolve_binary_target` when the raw path doesn't exist.
_REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY_TARGETS_ROOT: str = os.getenv(
    "R2_BINARY_TARGETS_ROOT", os.path.join(_REPO_ROOT, "binaries")
)

# Magic-byte signatures for the formats r2 can meaningfully open.  The key
# is a human-readable format label; the value is (offset, magic_bytes).
_BINARY_MAGIC: List[Tuple[str, int, bytes]] = [
    ("ELF",     0, b"\x7fELF"),
    ("PE",      0, b"MZ"),
    ("Mach-O",  0, b"\xfe\xed\xfa\xce"),     # 32-bit BE
    ("Mach-O",  0, b"\xfe\xed\xfa\xcf"),     # 64-bit BE
    ("Mach-O",  0, b"\xcf\xfa\xed\xfe"),     # 64-bit LE
    ("Mach-O",  0, b"\xce\xfa\xed\xfe"),     # 32-bit LE
    ("Java",    0, b"\xca\xfe\xba\xbe"),     # .class / JAR
    ("WebAssembly", 0, b"\x00asm"),
    # COFF / object files share no single magic at offset 0, so we rely on
    # the null-byte heuristic below as a fallback for those.
]

# Directories to skip when walking the drop folder.
_SKIP_DIRS = {".git", ".github", "__pycache__", "node_modules", ".venv", "venv"}


def detect_binary_format(path: str) -> Optional[str]:
    """Sniff the first bytes of ``path`` for a known binary magic.

    Returns a format label (``"ELF"``, ``"PE"``, ``"Mach-O"`` …) or ``None``
    if the file is not a recognised binary.  A secondary heuristic — a NUL
    byte within the first 512 bytes — catches COFF/object files and other
    non-text binaries that lack a unique offset-0 magic.  This never spawns
    an external process (``file`` / ``rabin2``); it is a cheap header read.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if not head:
        return None
    for label, offset, magic in _BINARY_MAGIC:
        if head[offset:offset + len(magic)] == magic:
            return label
    # Fallback: NUL byte in the first 512 bytes is a strong "not text"
    # signal and catches .o / .a / arbitrary object files r2 can still open.
    if b"\x00" in head:
        return "binary"
    return None


def resolve_binary_target(target: str) -> Optional[str]:
    """Resolve ``target`` to an absolute path, searching the drop folder.

    If ``target`` is already an existing path (absolute or relative to CWD),
    it is honoured as-is.  Otherwise the drop folder (:data:`BINARY_TARGETS_ROOT`)
    is searched for a matching filename — first an exact relative-path match
    (e.g. ``subdir/crackme``), then a bare-name recursive match (e.g.
    ``crackme`` finds ``binaries/crackmes/crackme``).  Returns the absolute
    path string if found, otherwise ``None``.  Never raises.
    """
    if not target:
        return None
    p = os.path.abspath(target)
    if os.path.isfile(p):
        return p
    root = BINARY_TARGETS_ROOT
    if not os.path.isdir(root):
        return None
    # Exact relative path under the drop folder.
    candidate = os.path.join(root, target)
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    # Bare-name recursive search (last-resort, but the common case when the
    # model only knows the filename it saw in ``list_r2_targets``).
    base = os.path.basename(target)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if base in filenames:
            return os.path.abspath(os.path.join(dirpath, base))
    return None


def discover_binary_targets(
    root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Walk the binary drop folder and return recognised binary files.

    Yields a list of dicts sorted by path, each with:

    - ``name`` — bare filename (what the model passes to ``run_r2``).
    - ``path`` — absolute path.
    - ``rel_path`` — path relative to the drop folder root.
    - ``size`` — file size in bytes.
    - ``format`` — detected format label (``"ELF"``, ``"PE"`` …) or
      ``"binary"`` for the NUL-byte heuristic.

    Files that don't match any binary magic (text, images, archives without
    a recognised header) are skipped so the listing stays clean.
    """
    base = root or BINARY_TARGETS_ROOT
    if not os.path.isdir(base):
        return []
    results: List[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in sorted(filenames):
            if fname.startswith("."):
                continue
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            fmt = detect_binary_format(fpath)
            if fmt is None:
                continue
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            rel = os.path.relpath(fpath, base)
            results.append({
                "name": fname,
                "path": os.path.abspath(fpath),
                "rel_path": rel,
                "size": size,
                "format": fmt,
            })
    results.sort(key=lambda r: r["rel_path"])
    return results


# ---------------------------------------------------------------------------
# r2ghidra preflight — cached once per process
# ---------------------------------------------------------------------------
_r2ghidra_status: Optional[bool] = None  # None=unchecked, True/False=cached


def _r2ghidra_available() -> bool:
    """Return True if the r2ghidra decompiler plugin is loadable.

    Probed once per process and cached in ``_r2ghidra_status``.  We detect
    by running ``pdg`` on a zero-byte throwaway file and checking for r2's
    own "install the plugin" sentinel — this is version-agnostic and does
    not depend on r2pm internals.  A zero-byte file is enough: r2 loads the
    plugin at startup regardless of file content, and the sentinel appears
    in stdout when the plugin is absent.
    """
    global _r2ghidra_status
    if _r2ghidra_status is not None:
        return _r2ghidra_status

    r2_bin = shutil.which("r2")
    if r2_bin is None:
        # No r2 at all — pdg is certainly unavailable.
        _r2ghidra_status = False
        return False

    fd, tmp = tempfile.mkstemp(suffix=".bin")
    os.close(fd)  # empty file — just a probe vehicle
    try:
        proc = subprocess.run(
            [r2_bin, "-q", "-e", "scr.color=0", "-e", "scr.utf8=0",
             "-c", "pdg @ 0", tmp],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        _r2ghidra_status = False
        return False
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    combined = (proc.stdout or "") + (proc.stderr or "")
    # r2 emits exactly this when the plugin is missing.
    _r2ghidra_status = "install the plugin" not in combined.lower()
    return _r2ghidra_status


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _check_forbidden(value: str, field: str) -> Optional[str]:
    """Return an error message if ``value`` contains a forbidden char, else None."""
    if value is None:
        return None
    for ch in _FORBIDDEN_CHARS:
        if ch in value:
            return (
                f"forbidden character {ch!r} in {field!r} — "
                f"r2 -c splits on ';' and newline; other chars are "
                f"shell-significant. Input rejected."
            )
    return None


def _validate_addr(addr: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Validate ``addr`` against the strict charset.

    Returns ``(normalized_addr, error_msg)``.  On success ``error_msg`` is
    None.  A None addr is only valid for commands that don't take one
    (caller checks that separately).
    """
    if addr is None or addr == "":
        return (addr, None)

    # Layer 2: forbidden-char scan.
    err = _check_forbidden(addr, "addr")
    if err:
        return (None, err)

    # Layer 3: strict charset — hex int or flag/symbol name.
    # If it starts with 0x it MUST be valid hex (don't fall through to the
    # flag charset, otherwise "0xGGG" sneaks through as a "name").  A bare
    # all-digit string is rejected (ambiguous — require the 0x prefix for
    # numeric addresses; real flag names like "entry0", "sym.main",
    # "fcn.00401000" always contain a non-digit character).
    if addr.lower().startswith("0x"):
        if _ADDR_HEX_RE.match(addr):
            return (addr, None)
        return (
            None,
            f"addr {addr!r} starts with 0x but is not valid hex "
            f"(0x[0-9a-fA-F]+); rejected",
        )
    if _ADDR_FLAG_RE.match(addr) and not addr.isdigit():
        return (addr, None)

    return (
        None,
        f"addr {addr!r} must be a hex integer (0x[0-9a-fA-F]+) or a "
        f"flag/symbol name ([A-Za-z0-9_.$-]+, must contain a non-digit); "
        f"rejected",
    )


def _validate_count(count: Any, cap: int) -> Tuple[Optional[int], Optional[str]]:
    """Coerce ``count`` to int and clamp to ``cap``.  Returns (value, error)."""
    if count is None:
        return (None, None)
    try:
        n = int(count)
    except (TypeError, ValueError):
        return (None, f"count must be an integer, got {count!r}")
    if n < 1:
        return (None, f"count must be >= 1, got {n}")
    if n > cap:
        n = cap  # clamp, don't reject — the model shouldn't fail over a cap
    return (n, None)


# ---------------------------------------------------------------------------
# Command composition
# ---------------------------------------------------------------------------
def _compose_cmd(command: str, addr: Optional[str], count: Optional[int]) -> str:
    """Build the r2 ``-c`` string from validated pieces.

    The tool owns the ``;`` (chaining ``aaa``) and the ``@`` (seek).  User
    input never contributes either character.  Shape::

        aaa; <verb> [<count>] [@ <addr>]
    """
    needs_addr, needs_count, _, _ = _COMMAND_TABLE[command]
    # Build the user-command segment, then append the seek modifier to THAT
    # segment — "@ addr" is a modifier on the command, not a separate r2
    # command, so it must NOT be joined with "; " (which would yield
    # "aaa; pdf; @ main" and make r2 run a bare "pdf" with no seek).
    cmd_str = command
    if needs_count and count is not None:
        cmd_str = f"{command} {count}"
    if needs_addr and addr:
        cmd_str = f"{cmd_str} @ {addr}"
    return f"aaa; {cmd_str}"


# ---------------------------------------------------------------------------
# Context-aware next-hints — guide the model's next step
# ---------------------------------------------------------------------------
def _hints_for(command: str, output: str) -> List[str]:
    """Return curated next-action hints based on what was just run."""
    hints: List[str] = []
    if command == "afl":
        hints.append("pdf @ <addr> to disassemble a listed function")
        hints.append("pdg @ <addr> to decompile it (if r2ghidra installed)")
        hints.append("axt @ <addr> to see what calls it")
    elif command == "iI":
        hints.append("iS for sections, ii for imports, is for symbols")
        hints.append("izz to hunt strings (creds/paths/URLs) across the file")
    elif command in ("izz", "iz"):
        hints.append("ps @ <addr> to read a specific string fully")
        hints.append("axt @ <addr> to find what references a string")
    elif command == "pdf":
        hints.append("pdg @ <same addr> for decompiled C pseudocode")
        hints.append("axt @ <addr> to find callers of this function")
    elif command == "pdg":
        hints.append("pdf @ <same addr> for raw disassembly")
        hints.append("pdf @ <addr> to see what this function calls (read the call instructions)")
    elif command == "axt":
        hints.append("pdf @ <caller addr> to inspect the calling function")
    elif command == "axf":
        # axf is broken on function-flag targets in r2 >=6.x (returns empty
        # even when calls exist); it still works on instruction addresses.
        hints.append("pdf @ <callee addr> to inspect the called function")
        hints.append("note: axf may return empty on function flags - use pdf to read calls")
    elif command == "afi":
        hints.append("pdf @ <addr> to disassemble this function")
        hints.append("pdg @ <addr> to decompile it")
    elif command == "af":
        hints.append("pdf @ <addr> to disassemble the now-analyzed function")
    elif command in ("iE", "is"):
        hints.append("axt @ <symbol addr> to find cross-references to it")
        hints.append("pdf @ <addr> to disassemble a function symbol")
    elif command == "iS":
        hints.append("izz to enumerate strings")
        hints.append("px <len> @ <section addr> to hexdump a section")
    elif command == "ii":
        hints.append("axt @ <import plt addr> to find callers of an import")
    elif command == "ps":
        hints.append("axt @ <addr> to find what references this string")
    hints.append("report_finding to record a discovered artifact")
    return hints


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------
@framework_tool(
    "Static binary analysis with radare2: disassemble, decompile (r2ghidra), "
    "enumerate symbols/imports/exports/sections/strings, and query cross-"
    "references against an ELF/PE/Mach-O binary. One composite tool — pass a "
    "command verb from the allowlist (aaa, afl, afi, af, iI, iS, iE, ii, is, "
    "iR, iz, izz, pdf, pdg, pd, px, axt, axf, ps) plus an optional addr "
    "(hex int like 0x401000 or flag name like sym.main) and optional count "
    "(for pd/px). Runs read-only against a temp copy of the binary; analysis "
    "(aaa) is always prepended. Output is truncated with a stated policy on "
    "fat binaries.",
    next_hints=["report_finding"],
)
def run_r2(
    target: str,
    command: str,
    addr: Optional[str] = None,
    count: Optional[int] = None,
) -> Dict[str, Any]:
    """Run a single radare2 command against a binary and return a structured envelope.

    Always opens with ``aaa`` (full analysis) so symbol-dependent commands
    work statelessly.  r2 runs against a per-run temp copy of ``target``
    (read-only — never ``-w``), which is cleaned up after.  The composed
    ``-c`` string is built by this function from validated pieces; the caller
    never supplies ``;`` or ``@``.

    Args:
        target: Path to the binary to analyze.  Must exist and be readable.
        command: One r2 verb from the frozen allowlist (exact match only).
        addr: Optional target address — hex integer (``0x401000``) or
            flag/symbol name (``sym.main``, ``entry0``).  Required for
            commands marked as needing an addr in the table (pdf, pdg, pd,
            px, afi, af, axt, axf, ps); ignored for metadata commands.
        count: Optional integer for ``pd`` (instruction count, capped at
            512) and ``px`` (byte count, capped at 1024).  Ignored by other
            commands.

    Returns:
        A dict envelope with::

            status        — "ok" | "error"
            command       — the composed r2 -c string that ran
            summary       — one-line human-readable result
            output        — r2 stdout (truncated if over R2_OUTPUT_CAP)
            stderr        — r2 stderr (captured separately, always present)
            exit_code     — r2 process exit code (int; -1 on launch failure)
            truncated     — bool
            truncation_policy — stated policy string if truncated, else None
            target        — the original target path
            r2ghidra      — bool, whether the decompiler plugin is available
            next_hints    — curated next-action suggestions
            delta         — short note on what this run surfaced
            error         — present only on status="error"
    """
    # --- Layer 1: exact allowlist match on command ---
    if command is None or command not in _COMMAND_TABLE:
        return _err_envelope(
            target, command,
            f"command {command!r} is not in the allowlist "
            f"({', '.join(ALLOWED_COMMANDS)}); rejected",
        )

    # --- Layer 2: forbidden-char scan on command (belt + braces) ---
    err = _check_forbidden(command, "command")
    if err:
        return _err_envelope(target, command, err)

    needs_addr, needs_count, count_cap, _ = _COMMAND_TABLE[command]

    # --- Layer 2: forbidden-char scan on addr ---
    addr, err = _validate_addr(addr)
    if err:
        return _err_envelope(target, command, err)

    # addr required but not supplied?
    if needs_addr and not addr:
        return _err_envelope(
            target, command,
            f"command {command!r} requires an addr (hex int like 0x401000 "
            f"or flag name like sym.main); none supplied",
        )

    # --- Layer 4: integer caps on count ---
    count_val, err = _validate_count(count, count_cap)
    if err:
        return _err_envelope(target, command, err)
    if needs_count and count_val is None:
        count_val = 16 if command == "pd" else 64  # sensible defaults

    # --- r2ghidra preflight for pdg ---
    ghidra_ok = _r2ghidra_available()
    if command in _R2GHIDRA_COMMANDS and not ghidra_ok:
        return _err_envelope(
            target, command,
            "r2ghidra not installed — run: r2pm -ci r2ghidra  "
            "(pdg requires the r2ghidra decompiler plugin; all other "
            "commands work without it)",
            r2ghidra=False,
        )

    # --- target resolution: existing path, or auto-resolve from drop folder ---
    r2_bin = shutil.which("r2")
    if r2_bin is None:
        return _err_envelope(target, command, "radare2 (r2) not found on PATH")
    resolved = resolve_binary_target(target) if target else None
    if resolved is None:
        return _err_envelope(
            target, command,
            f"target {target!r} not found — no such file, and no match in "
            f"the binary drop folder ({BINARY_TARGETS_ROOT}). Call "
            f"list_r2_targets to see what is available.",
        )
    # Work against the resolved absolute path from here on.
    target = resolved

    # --- compose the -c string from validated pieces ---
    composed = _compose_cmd(command, addr, count_val)

    # --- per-run temp copy (read-only by construction: never -w) ---
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="r2work_", suffix=os.path.splitext(target)[1] or ".bin"
    )
    try:
        os.close(tmp_fd)
        shutil.copy2(target, tmp_path)
        # Read-only on the copy too — belt and braces.
        os.chmod(tmp_path, 0o444)

        argv = [
            r2_bin, "-q",
            "-e", "scr.color=0",
            "-e", "scr.utf8=0",
            "-c", composed,
            tmp_path,
        ]

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_R2_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return _err_envelope(
                target, command,
                f"r2 timed out after {_R2_TIMEOUT}s — try a more targeted "
                f"command or a smaller count; aaa on very large binaries can "
                f"be slow (raise R2_TIMEOUT env to widen)",
            )
        except Exception as exc:
            return _err_envelope(
                target, command, f"r2 launch failed: {exc}",
            )

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # --- truncation with stated policy ---
    raw_out = proc.stdout or ""
    truncated = len(raw_out) > _OUTPUT_CAP
    output = raw_out[:_OUTPUT_CAP] if truncated else raw_out

    # Strip r2's INFO/WARN noise from the summary view but keep it in output.
    clean_lines = [
        ln for ln in raw_out.splitlines()
        if not ln.startswith(("INFO:", "WARN:", " "))
        and ln.strip()
    ]

    summary = _summarize(command, clean_lines, addr)
    delta = _delta_note(command, clean_lines, addr)

    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "command": composed,
        "summary": summary,
        "output": output,
        "stderr": (proc.stderr or "").strip(),
        "exit_code": proc.returncode,
        "truncated": truncated,
        "truncation_policy": _TRUNCATION_NOTE if truncated else None,
        "target": target,
        "r2ghidra": ghidra_ok,
        "next_hints": _hints_for(command, output),
        "delta": delta,
    }


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------
def _err_envelope(
    target: str,
    command: Optional[str],
    error: str,
    r2ghidra: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build a consistent error envelope."""
    ghidra = _r2ghidra_available() if r2ghidra is None else r2ghidra
    return {
        "status": "error",
        "command": command,
        "summary": error,
        "output": "",
        "stderr": "",
        "exit_code": -1,
        "truncated": False,
        "truncation_policy": None,
        "target": target,
        "r2ghidra": ghidra,
        "next_hints": [],
        "delta": "",
        "error": error,
    }


def _summarize(command: str, clean_lines: List[str], addr: Optional[str]) -> str:
    """One-line human summary of the r2 output."""
    n = len(clean_lines)
    if n == 0:
        loc = f" @ {addr}" if addr else ""
        return f"{command}{loc}: no output (empty result)"
    first = clean_lines[0].strip()
    if n <= 3:
        loc = f" @ {addr}" if addr else ""
        return f"{command}{loc}: {n} line(s) — {first}"
    loc = f" @ {addr}" if addr else ""
    return f"{command}{loc}: {n} lines — first: {first[:120]}"


_TABLE_COMMANDS: frozenset = frozenset({"iz", "izz", "iE", "ii", "is", "iS"})


def _delta_note(command: str, clean_lines: List[str], addr: Optional[str]) -> str:
    """Short note on what this run surfaced (for the model's working memory).

    Table-format commands (iz, izz, iE, ii, is, iS) emit a header row and a
    separator row before the data rows.  We subtract 2 so the reported count
    reflects actual entities, not raw line count.
    """
    # For table commands, drop the header + separator to count real rows.
    entity_count = (
        max(0, len(clean_lines) - 2) if command in _TABLE_COMMANDS
        else len(clean_lines)
    )
    if command == "afl":
        return f"discovered {entity_count} function(s)"
    if command in ("izz", "iz"):
        return f"found {entity_count} string(s)"
    if command == "iI":
        # grab the arch line if present
        for ln in clean_lines:
            if ln.startswith("arch"):
                return f"binary arch: {ln}"
        return "binary metadata returned"
    if command == "iE":
        return f"{entity_count} export(s) listed"
    if command == "ii":
        return f"{entity_count} import(s) listed"
    if command == "is":
        return f"{entity_count} symbol(s) listed"
    if command == "iS":
        return f"{entity_count} section(s) listed"
    if command == "axt":
        return f"{len(clean_lines)} xref(s) TO {addr}"
    if command == "axf":
        return f"{len(clean_lines)} xref(s) FROM {addr}"
    if command == "pdf":
        return f"disassembled function @ {addr} ({len(clean_lines)} lines)"
    if command == "pdg":
        return f"decompiled function @ {addr} ({len(clean_lines)} lines)"
    if command == "afi":
        return f"function info @ {addr}"
    loc = f" @ {addr}" if addr else ""
    return f"{command}{loc}: {len(clean_lines)} line(s) of output"


# ---------------------------------------------------------------------------
# list_r2_targets — discover binaries in the drop folder
# ---------------------------------------------------------------------------
@framework_tool(
    "List binaries available for static analysis in the framework's binary "
    "drop folder (binaries/). Returns each file's name, detected format "
    "(ELF, PE, Mach-O, etc.), size, and relative path. Use this to discover "
    "what targets are available before calling run_r2 with a bare name — "
    "run_r2 auto-resolves names from this folder, so you only need the "
    "filename, not the full path. Drop new binaries into binaries/ (it is "
    "gitignored) and re-call this to see them.",
    next_hints=["run_r2"],
)
def list_r2_targets() -> Dict[str, Any]:
    """Enumerate recognised binary files in the drop folder.

    Walks :data:`BINARY_TARGETS_ROOT` (default ``binaries/`` at the repo
    root; override via ``R2_BINARY_TARGETS_ROOT`` env) recursively, filtering
    to files with a recognised binary magic header (ELF, PE, Mach-O, Java,
    WebAssembly, or a NUL-byte heuristic for object files).  Text files and
    junk are excluded so the listing stays clean.

    Returns:
        A dict with::

            status     — "ok" | "error"
            root       — the drop folder path that was walked
            count      — number of binaries found
            targets    — list of {name, path, rel_path, size, format}
            next_hints — curated next-action suggestions
    """
    root = BINARY_TARGETS_ROOT
    if not os.path.isdir(root):
        return {
            "status": "error",
            "root": root,
            "count": 0,
            "targets": [],
            "next_hints": [],
            "error": (
                f"binary drop folder {root!r} does not exist. Create it and "
                f"drop target binaries there (it is gitignored)."
            ),
        }
    targets = discover_binary_targets(root)
    return {
        "status": "ok",
        "root": root,
        "count": len(targets),
        "targets": targets,
        "next_hints": [
            "run_r2 with a target name from the list (e.g. run_r2('crackme', 'iI'))",
            "run_r2('<name>', 'aaa') then 'afl' to discover functions",
            "run_r2('<name>', 'izz') to hunt for embedded strings",
        ],
    }
