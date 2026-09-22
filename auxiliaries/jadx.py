"""Jadx static-analysis composite tool (``run_jadx``) + drop-folder discovery.

Mirrors :mod:`auxiliaries.radare2`: ONE composite ``@framework_tool`` driving an
external binary as a one-shot subprocess (argv list, ``shell=False``), plus one
discovery tool for a dedicated, gitignored drop folder.  Where r2 is an
in-memory disassembler that needs only a temp copy, jadx is a BATCH decompiler
— it must emit a tree of files.  That tree is cached per target under
``apk/decompiled/<basename>/`` and reused across calls, so the expensive run
happens once and every later ``grep``/``read``/``tree`` call is instant.

Scope-gate: NONE by design.  This is OFFLINE static analysis of an artifact the
operator dropped into ``apk/`` — jadx opens no sockets, makes no DNS requests,
contacts no target (same class as radare2/crypto_kit).  Documented here so a
future "hardening" pass does not silently gate an offline lane.

Threat model & validation (defense in depth)
--------------------------------------------
The model supplies free text; the tool composes the argv itself.  jadx takes no
command language (unlike ``r2 -c``), so the classic ``;``-chain risk does not
exist; the injection-adjacent surface is argument composition and output paths.

1. **Exact verb allowlist** — ``command`` must match one of 6 frozen verbs
   (8 slots reserved).  No substring, no prefix match.
2. **Argv-list subprocess** — ``shell=False`` always; no caller text is ever
   joined into a shell string.  The output dir (``-d``/``--single-class-output``)
   is ALWAYS tool-composed inside the workspace root, never caller-supplied.
3. **Charset locks** — ``single_class`` must be a Java FQN shape
   (``[A-Za-z0-9_.$-]+``); ``glob`` must be a plain fnmatch token (no spaces,
   quotes, shell chars); ``pattern`` (grep) is compiled as a Python regex —
   it never touches a shell or a jadx arg.
4. **Traversal guards** — ``read`` paths are resolved and must stay inside the
   decompiled workspace (``..``/absolute rejected).  Drop-folder resolution and
   workspace wipe (``force``) both verify containment before touching disk.
5. **Integer caps & truncation** — ``threads`` clamped 1..16; grep caps
   (256-char pattern, 200 matches, 4000 files, 2 MiB/file); ``tree`` caps its
   listing; every byte-bearing output is truncated at ``JADX_OUTPUT_CAP`` with
   a stated policy so the model knows it saw a prefix.
6. **Subprocess timeout** — ``JADX_TIMEOUT`` env (default 900 s).  Full-apk
   decompiles can take minutes on big targets; the Brain's
   ``BRAIN_EXEC_CEILING`` (default 3600) is the outer bound.
7. **jadx-side hardening** — jadx 1.5.6 itself rejects absolute/escaping zip
   entry paths (zip-slip) and hardens XML parsing, so a malicious dropped APK
   writing outside its workspace is doubly refused.

Preflight
---------
``jadx`` needs a Java 11+ runtime (system JRE).  Resolution order: ``$JADX_BIN``
env -> ``PATH`` -> common install paths.  Missing binary or missing ``java``
returns a clean envelope with the exact install hint (no reindex needed —
preflight runs at call time, like the john/hashcat wrappers).  The version is
probed once per process and cached.

Verb set
--------
- ``decompile`` — full decompile into the per-target workspace
  (``sources/`` + ``resources/``).  Cached: re-run only when the source file
  fingerprint (mtime_ns+size) changes or ``force=True``.  Params: ``deobf``,
  ``show_bad_code``, ``mode`` (auto|restructure|simple|fallback), ``threads``,
  ``no_res``, ``force``.
- ``manifest`` — decode ``AndroidManifest.xml`` only (fast resources-only
  jadx pass, ``-s``); returns the XML, capped.
- ``class`` — targeted single-class pull via ``--single-class`` (the recon
  workhorse before committing to a full decompile).  Param: ``single_class``.
- ``grep`` — bounded regex search over the decompiled workspace (needs an
  existing workspace — decompile first).  Params: ``pattern``, ``glob``,
  ``case_insensitive``.
- ``read`` — bounded single-file read from the workspace.  Param: ``path``.
- ``tree`` — bounded workspace file listing, optional ``glob`` filter.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool


# ---------------------------------------------------------------------------
# Frozen verb table — schema-verified against jadx 1.5.6 (2026-07-10 release;
# JadxCLIArgs flags: -d, -r/--no-res, -s/--no-src, -j/--threads-count,
# --single-class(+ --single-class-output), --decompilation-mode, --deobf,
# --show-bad-code).  6 slots filled; slots 7-8 held open for practice gaps.
# verb -> blurb
# ---------------------------------------------------------------------------
_VERB_TABLE: Dict[str, str] = {
    "decompile": "full decompile into the per-target workspace (cached; params: deobf/show_bad_code/mode/threads/no_res/force)",
    "manifest":  "decode AndroidManifest.xml only (fast resources-only pass; returns the XML)",
    "class":     "pull ONE class's decompiled source via --single-class (params: single_class='com.example.Foo')",
    "grep":      "regex search over the decompiled workspace (params: pattern, glob, case_insensitive)",
    "read":      "read one decompiled file, bounded (param: path, relative to the workspace)",
    "tree":      "list workspace files, bounded, optional glob filter (param: glob)",
    # slots 7-8: reserved for practice-found gaps (candidate: --call-graph dot/json export)
}

ALLOWED_VERBS: tuple = tuple(_VERB_TABLE.keys())

_DECOMPILE_MODES: tuple = ("auto", "restructure", "simple", "fallback")

# ---------------------------------------------------------------------------
# Caps / tuning (env-overridable, mirroring R2_OUTPUT_CAP / R2_TIMEOUT)
# ---------------------------------------------------------------------------
_OUTPUT_CAP: int = int(os.getenv("JADX_OUTPUT_CAP", str(200 * 1024)))
_TRUNCATION_NOTE: str = (
    f"output capped at {_OUTPUT_CAP} bytes (JADX_OUTPUT_CAP env) — "
    "this is a prefix, not the full result; narrow the query"
)
_JADX_TIMEOUT: float = float(os.getenv("JADX_TIMEOUT", "900"))
_PATTERN_CAP: int = 256
_GREP_MAX_MATCHES: int = 200
_GREP_MAX_FILES: int = 4000
_GREP_MAX_FILE_BYTES: int = 2 * 1024 * 1024
_TREE_LIST_CAP: int = 500
_THREADS_MIN, _THREADS_MAX = 1, 16
_CLASS_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_.$-]{1,256}$")
_GLOB_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_*?.\-/]{1,256}$")

# Text-ish extensions scanned by the grep verb (resources include xml/html/js).
_GREP_TEXT_EXTS: frozenset = frozenset({
    ".java", ".kt", ".xml", ".json", ".txt", ".smali", ".gradle", ".pro",
    ".yml", ".yaml", ".properties", ".csv", ".html", ".js", ".md", ".cfg",
    ".aidl", ".jsp", ".ini", ".conf",
})

# ---------------------------------------------------------------------------
# Drop folder — discovery & resolution (mirrors binaries/ + R2_BINARY_TARGETS_ROOT)
# ---------------------------------------------------------------------------
_REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK_TARGETS_ROOT: str = os.getenv(
    "JADX_APK_TARGETS_ROOT", os.path.join(_REPO_ROOT, "apk")
)
_DECOMPILED_SUBDIR: str = "decompiled"  # workspaces live here; never listed
_MANIFEST_REL: str = os.path.join("resources", "AndroidManifest.xml")
_META_NAME: str = ".jadx_meta.json"

# Magic-byte signatures for the inputs jadx accepts.  (apk/xapk/apkm/aab/
# aar/jar/zip/apks are all ZIP-family; the extension refines the label.)
_APK_MAGIC: List[tuple] = [
    ("ZIP-family", 0, b"PK\x03\x04"),            # apk/jar/zip/xapk/apkm/aab/aar
    ("DEX",       0, b"dex\n"),                  # raw classes.dex
    ("Java-class", 0, b"\xca\xfe\xba\xbe"),      # raw .class
    ("ARSC",      0, b"\x02\x00\x0c\x00"),       # resources.arsc table chunk
]

_SKIP_DIRS: frozenset = frozenset({
    ".git", ".github", "__pycache__", "node_modules", ".venv", "venv",
    _DECOMPILED_SUBDIR,
})

_ZIP_EXT_LABELS: Dict[str, str] = {
    ".apk": "APK", ".xapk": "XAPK", ".apkm": "APKM", ".apks": "APKS",
    ".aab": "AAB", ".aar": "AAR", ".jar": "JAR", ".zip": "ZIP",
}


def detect_apk_format(path: str) -> Optional[str]:
    """Sniff the first bytes of ``path`` for a format jadx accepts.

    Returns a human label (``"APK"``, ``"DEX"``, ``"ZIP-family"`` …) or
    ``None``.  Pure header read — never spawns a process (no ``file`` call).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if not head:
        return None
    for label, offset, magic in _APK_MAGIC:
        if head[offset:offset + len(magic)] == magic:
            if label == "ZIP-family":
                ext = os.path.splitext(path)[1].lower()
                if ext in _ZIP_EXT_LABELS:
                    return _ZIP_EXT_LABELS[ext]
                return "ZIP-family"
            return label
    return None


def resolve_apk_target(target: str) -> Optional[str]:
    """Resolve ``target`` to an absolute path, searching the drop folder.

    Existing paths are honoured as-is; otherwise the drop folder
    (:data:`APK_TARGETS_ROOT`) is searched — exact relative-path match first,
    then bare-name recursive match.  Never raises.
    """
    if not target:
        return None
    p = os.path.abspath(target)
    if os.path.isfile(p):
        return p
    root = APK_TARGETS_ROOT
    if not os.path.isdir(root):
        return None
    candidate = os.path.join(root, target)
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    base = os.path.basename(target)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if base in filenames:
            return os.path.abspath(os.path.join(dirpath, base))
    return None


def discover_apk_targets(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Walk the apk drop folder and return recognised jadx-able files.

    Skips the ``decompiled/`` workspace subtree and dot-directories.  Each hit:
    ``{name, path, rel_path, size, format}``.
    """
    base = root or APK_TARGETS_ROOT
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
            fmt = detect_apk_format(fpath)
            if fmt is None:
                continue
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            results.append({
                "name": fname,
                "path": os.path.abspath(fpath),
                "rel_path": os.path.relpath(fpath, base),
                "size": size,
                "format": fmt,
            })
    results.sort(key=lambda r: r["rel_path"])
    return results


# ---------------------------------------------------------------------------
# Preflight — jadx binary + java runtime (cached version probe)
# ---------------------------------------------------------------------------
_COMMON_JADX_PATHS: tuple = (
    "/usr/local/bin/jadx", "/usr/bin/jadx", "/opt/jadx/bin/jadx",
    os.path.expanduser("~/jadx/bin/jadx"),
)

_jadx_version_cache: Optional[str] = None  # "" = probed-and-unavailable


def resolve_jadx_bin() -> Optional[str]:
    """Locate jadx: $JADX_BIN -> PATH -> common install paths."""
    env_bin = os.getenv("JADX_BIN", "").strip()
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    found = shutil.which("jadx")
    if found:
        return found
    for cand in _COMMON_JADX_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _jadx_version() -> Optional[str]:
    """Probe ``jadx --version`` once per process; None when unavailable."""
    global _jadx_version_cache
    if _jadx_version_cache is not None:
        return _jadx_version_cache
    jadx_bin = resolve_jadx_bin()
    if jadx_bin is None:
        _jadx_version_cache = ""
        return None
    try:
        proc = subprocess.run(
            [jadx_bin, "--version"],
            capture_output=True, text=True, timeout=15,
        )
        ver = (proc.stdout or "").strip().splitlines()[0] if proc.stdout else ""
        _jadx_version_cache = ver or ""
    except Exception:
        _jadx_version_cache = ""
    return _jadx_version_cache or None


def _preflight_or_none(target: str, verb: str) -> Optional[Dict[str, Any]]:
    """Return an error envelope when jadx/java are unavailable, else None.

    Preflight lives ONLY in the verbs that spawn jadx (decompile / manifest /
    class).  grep/read/tree are pure-Python workspace readers and work without
    jadx installed — cached decompiled trees stay usable while the binary is
    being installed.  Clean envelopes; no reindex needed after install —
    preflight runs at call time (like the john/hashcat wrappers).
    """
    if resolve_jadx_bin() is None:
        return _err_verb(
            target, verb,
            "jadx not found — install the 1.5.x release bundle "
            "(github.com/skylot/jadx) and put bin/jadx on PATH, or set the "
            "JADX_BIN env var; requires a Java 11+ JRE. No reindex needed "
            "after install — preflight runs at call time.",
        )
    if not _java_available():
        return _err_verb(
            target, verb,
            "jadx found but no Java runtime on PATH — jadx requires a "
            "Java 11+ JRE (e.g. apt install default-jre).",
        )
    return None


def _java_available() -> bool:
    """Java 11+ runtime present on PATH?  (Seam for offline tests.)"""
    return shutil.which("java") is not None


# ---------------------------------------------------------------------------
# Workspace cache (per-target decompiled tree) — the jadx analog of r2's
# temp copy.  jadx MUST write a file tree, so the workspace persists and is
# reused; a fingerprint (mtime_ns + size) decides stale vs. fresh.
# ---------------------------------------------------------------------------
def _workspace_for(source_path: str) -> str:
    base = os.path.basename(source_path)
    return os.path.join(APK_TARGETS_ROOT, _DECOMPILED_SUBDIR, base)


def _stat_fingerprint(source_path: str) -> Dict[str, Any]:
    st = os.stat(source_path)
    return {"source_mtime_ns": st.st_mtime_ns, "source_size": st.st_size}


def _read_meta(ws: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(ws, _META_NAME), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_meta(ws: str, source_path: str, jadx_ver: Optional[str]) -> None:
    meta = dict(_stat_fingerprint(source_path))
    meta["jadx_version"] = jadx_ver
    meta["source"] = os.path.basename(source_path)
    try:
        with open(os.path.join(ws, _META_NAME), "w") as fh:
            json.dump(meta, fh, indent=1)
    except OSError:
        pass  # cache bookkeeping must never fail the run


def _workspace_state(ws: str, source_path: str) -> Dict[str, Any]:
    """Inspect the workspace: exists / has sources / has manifest / stale."""
    exists = os.path.isdir(ws)
    state: Dict[str, Any] = {
        "exists": exists,
        "has_sources": False,
        "has_manifest": False,
        "stale": False,
    }
    if not exists:
        return state
    state["has_sources"] = os.path.isdir(os.path.join(ws, "sources"))
    state["has_manifest"] = os.path.isfile(os.path.join(ws, _MANIFEST_REL))
    try:
        meta = _read_meta(ws)
        fp = _stat_fingerprint(source_path)
        state["stale"] = bool(
            not meta
            or meta.get("source_mtime_ns") != fp["source_mtime_ns"]
            or meta.get("source_size") != fp["source_size"]
        )
    except OSError:
        state["stale"] = True
    return state


def _safe_ws_child(ws: str, rel_path: str) -> Optional[str]:
    """Resolve ``rel_path`` inside ``ws``, refusing traversal.  None = refuse."""
    if not rel_path:
        return None
    if rel_path.startswith(("/", "~")):
        return None
    parts = rel_path.replace("\\", "/").split("/")
    if any(p == ".." for p in parts):
        return None
    candidate = os.path.join(ws, rel_path)
    real_ws = os.path.realpath(ws)
    real_cand = os.path.realpath(candidate)
    try:
        if os.path.commonpath([real_ws, real_cand]) != real_ws:
            return None
    except ValueError:
        return None
    return candidate


def _clip(text: str) -> tuple:
    """Truncate to the output cap.  Returns (text, truncated)."""
    if len(text) > _OUTPUT_CAP:
        return text[:_OUTPUT_CAP], True
    return text, False


def _run_jadx_argv(argv: List[str]) -> tuple:
    """Run a composed jadx argv.  Returns (proc, error_message)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_JADX_TIMEOUT,
        )
        return proc, None
    except subprocess.TimeoutExpired:
        return None, (
            f"jadx timed out after {_JADX_TIMEOUT}s (JADX_TIMEOUT env) — "
            "big APKs can take minutes; raise the cap or narrow the request"
        )
    except Exception as exc:
        return None, f"jadx launch failed: {exc}"


# ---------------------------------------------------------------------------
# The discovery tool
# ---------------------------------------------------------------------------
@framework_tool(
    "List APKs/dex/jars available for apk disassembly and decompilation in "
    "the framework's apk drop folder (apk/). Returns each file's name, "
    "detected format (APK, DEX, JAR, XAPK, AAB, etc.), size, and relative "
    "path. Drop new targets into apk/ (gitignored) and re-call this; "
    "run_jadx auto-resolves bare names from this folder, so you only need "
    "the filename.",
    next_hints=["run_jadx"],
)
def list_apk_targets() -> Dict[str, Any]:
    """Enumerate recognised files in the apk drop folder.

    Walks :data:`APK_TARGETS_ROOT` (default ``apk/`` at the repo root;
    override via ``JADX_APK_TARGETS_ROOT`` env) recursively, filtering to
    jadx-acceptable magic headers (ZIP-family = apk/xapk/apkm/aab/aar/jar/zip,
    raw .dex, .class, .arsc).  The ``decompiled/`` workspace subtree is
    excluded so outputs never pollute the listing.

    Returns a dict with ``status, root, count, targets, jadx_version,
    next_hints``.
    """
    jadx_bin = resolve_jadx_bin()
    root = APK_TARGETS_ROOT
    if not os.path.isdir(root):
        return {
            "status": "error",
            "root": root,
            "count": 0,
            "targets": [],
            "jadx_version": _jadx_version(),
            "next_hints": [],
            "error": (
                f"apk drop folder {root!r} does not exist. Create it and drop "
                f"targets there (gitignored), or set JADX_APK_TARGETS_ROOT."
            ),
        }
    targets = discover_apk_targets(root)
    hints = [
        "run_jadx('<name>', 'manifest') — fast AndroidManifest.xml pull",
        "run_jadx('<name>', 'class', single_class='com.example.Foo') — one class, no full decompile",
        "run_jadx('<name>', 'decompile') — full decompile into the cached workspace",
    ]
    if jadx_bin is None:
        hints.insert(0, (
            "jadx not on PATH — install the 1.5.x release bundle and put "
            "bin/jadx on PATH, or set the JADX_BIN env var"
        ))
    return {
        "status": "ok",
        "root": root,
        "count": len(targets),
        "targets": targets,
        "jadx_version": _jadx_version(),
        "next_hints": hints,
    }


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------
def _verb_decompile(
    target: str, deobf: bool, show_bad_code: bool, mode: str,
    threads: Optional[int], no_res: bool, force: bool,
) -> Dict[str, Any]:
    ws = _workspace_for(target)
    state = _workspace_state(ws, target)
    if state["exists"] and not state["stale"] and state["has_sources"] and not force:
        n_java = _count_by_ext(ws, ".java")
        return {
            "status": "ok",
            "verb": "decompile",
            "summary": (
                f"workspace cached and fingerprint-fresh — {n_java} .java "
                f"file(s); use force=True to re-decompile"
            ),
            "workspace": ws,
            "cached": True,
            "java_source_count": n_java,
            "stale": False,
            "output": "",
            "truncated": False,
            "truncation_policy": None,
            "target": target,
            "jadx_version": _jadx_version(),
            "next_hints": [
                "run_jadx('<name>', 'grep', pattern='<regex>') to hunt creds/routes/secrets",
                "run_jadx('<name>', 'read', path='<rel path>') to pull one source file",
                "run_jadx('<name>', 'manifest') for AndroidManifest.xml",
            ],
            "delta": f"workspace reuse ({n_java} sources on disk)",
        }
    if state["exists"] and (state["stale"] or force):
        preflight = _preflight_or_none(target, "decompile")
        if preflight:
            return preflight
        shutil.rmtree(ws, ignore_errors=True)  # inside decompiled/ only
    elif not state["exists"]:
        preflight = _preflight_or_none(target, "decompile")
        if preflight:
            return preflight
    os.makedirs(ws, exist_ok=True)
    argv = [resolve_jadx_bin(), "-q", "-d", ws]
    if no_res:
        argv.append("-r")
    if deobf:
        argv.append("--deobf")
    if show_bad_code:
        argv.append("--show-bad-code")
    if mode != "auto":
        argv.extend(["--decompilation-mode", mode])
    if threads:
        argv.extend(["-j", str(threads)])
    argv.append(target)
    proc, err = _run_jadx_argv(argv)
    if err:
        return _err_verb(target, "decompile", err)
    n_java = _count_by_ext(ws, ".java")
    n_res = _count_all(ws, skip="sources") - n_java
    _write_meta(ws, target, _jadx_version())
    stderr_tail = (proc.stderr or "").strip()[-2000:]
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "verb": "decompile",
        "summary": (
            f"decompiled → {n_java} .java source(s), {max(0, n_res)} other file(s) "
            f"in {ws} (exit {proc.returncode})"
        ),
        "workspace": ws,
        "cached": False,
        "java_source_count": n_java,
        "exit_code": proc.returncode,
        "stderr_tail": stderr_tail,
        "stale": False,
        "output": "",
        "truncated": False,
        "truncation_policy": None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'grep', pattern='api_key|token|secret')",
            "run_jadx('<name>', 'tree', glob='sources/com/<pkg>/*')",
            "run_jadx('<name>', 'read', path='sources/com/<pkg>/MainActivity.java')",
            "report_finding to record a discovered artifact",
        ],
        "delta": f"fresh decompile ({n_java} sources); exit {proc.returncode}",
    }


def _verb_manifest(target: str) -> Dict[str, Any]:
    ws = _workspace_for(target)
    manifest_path = os.path.join(ws, _MANIFEST_REL)
    state = _workspace_state(ws, target)
    if not (state["exists"] and state["has_manifest"] and not state["stale"]):
        preflight = _preflight_or_none(target, "manifest")
        if preflight:
            return preflight
        # resources-only top-up (-s/--no-src keeps the fast path cheap)
        if state["exists"] and state["stale"]:
            shutil.rmtree(ws, ignore_errors=True)
        os.makedirs(ws, exist_ok=True)
        argv = [resolve_jadx_bin(), "-q", "-s", "-d", ws, target]
        proc, err = _run_jadx_argv(argv)
        if err:
            return _err_verb(target, "manifest", err)
        if proc.returncode != 0:
            return _err_verb(
                target, "manifest",
                f"jadx resources-only pass failed (exit {proc.returncode}): "
                f"{(proc.stderr or '').strip()[-1500:]}",
            )
        _write_meta(ws, target, _jadx_version())
    safe = _safe_ws_child(ws, _MANIFEST_REL)
    if safe is None or not os.path.isfile(safe):
        return _err_verb(
            target, "manifest",
            f"no decoded {os.path.basename(target)} at resources/AndroidManifest.xml — "
            f"is this an Android target? (plain jars/dex have no manifest)",
        )
    with open(safe, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    content, truncated = _clip(content)
    return {
        "status": "ok",
        "verb": "manifest",
        "summary": f"AndroidManifest.xml decoded ({len(content)} chars)",
        "output": content,
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": _TRUNCATION_NOTE if truncated else None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "exported activities/receivers/providers = the attack surface map",
            "run_jadx('<name>', 'grep', pattern='<manifest-string>') in sources",
            "report_finding to record an entry-point note",
        ],
        "delta": "manifest decoded",
    }


def _verb_class(target: str, single_class: Optional[str]) -> Dict[str, Any]:
    if not single_class or not _CLASS_RE.match(single_class):
        return _err_verb(
            target, "class",
            f"single_class {single_class!r} is not a valid Java class FQN "
            f"([A-Za-z0-9_.$-]+); rejected",
        )
    preflight = _preflight_or_none(target, "class")
    if preflight:
        return preflight
    jadx_bin = resolve_jadx_bin()
    tmp_dir = tempfile.mkdtemp(prefix="jadxclass_")
    try:
        argv = [
            jadx_bin, "-q",
            "--single-class", single_class,
            "--single-class-output", tmp_dir,
            target,
        ]
        proc, err = _run_jadx_argv(argv)
        if err:
            return _err_verb(target, "class", err)
        produced = [
            os.path.join(tmp_dir, f) for f in sorted(os.listdir(tmp_dir))
        ]
        if proc.returncode != 0 or not produced:
            return _err_verb(
                target, "class",
                f"single-class pull failed (exit {proc.returncode}): "
                f"{(proc.stderr or proc.stdout or '').strip()[-1500:]}",
            )
        out_file = produced[0]
        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        content, truncated = _clip(content)
        lines = content.count("\n") + 1
        return {
            "status": "ok",
            "verb": "class",
            "summary": (
                f"single-class pull {single_class}: {lines} line(s) "
                f"(exit {proc.returncode})"
            ),
            "output": content,
            "single_class": single_class,
            "truncated": truncated,
            "truncation_policy": _TRUNCATION_NOTE if truncated else None,
            "target": target,
            "jadx_version": _jadx_version(),
            "next_hints": [
                "run_jadx('<name>', 'decompile') to cache the whole tree for grep",
                "run_jadx('<name>', 'class', single_class='<next class>')",
                "report_finding to record a discovered behavior",
            ],
            "delta": f"pulled 1 class ({lines} lines)",
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _verb_grep(
    target: str, pattern: Optional[str], glob: Optional[str],
    case_insensitive: bool,
) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "grep",
            f"no decompiled workspace yet — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first (grep searches the cached tree, not the raw apk)",
        )
    if not pattern:
        return _err_verb(target, "grep", "pattern is required for the grep verb")
    if len(pattern) > _PATTERN_CAP:
        return _err_verb(
            target, "grep",
            f"pattern longer than {_PATTERN_CAP} chars; rejected",
        )
    try:
        rx = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
    except re.error as exc:
        return _err_verb(target, "grep", f"invalid regex: {exc}")
    if glob is not None and not _GLOB_RE.match(glob):
        return _err_verb(
            target, "grep",
            f"glob {glob!r} contains characters outside [A-Za-z0-9_*?.-/]; rejected",
        )
    import fnmatch
    matches: List[Dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0
    real_ws = os.path.realpath(ws)
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if files_scanned >= _GREP_MAX_FILES:
            break
        for fname in sorted(filenames):
            if files_scanned >= _GREP_MAX_FILES:
                break
            rel = os.path.relpath(os.path.join(dirpath, fname), ws)
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            if os.path.splitext(fname)[1].lower() not in _GREP_TEXT_EXTS:
                files_skipped += 1
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as fh:
                    blob = fh.read(_GREP_MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if b"\x00" in blob:  # binary — skip, don't regex bytes
                files_skipped += 1
                continue
            files_scanned += 1
            text = blob.decode("utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if rx.search(line):
                    matches.append({
                        "file": os.path.relpath(fpath, real_ws),
                        "line": line_no,
                        "text": line.strip()[:200],
                    })
                    if len(matches) >= _GREP_MAX_MATCHES:
                        break
            if len(matches) >= _GREP_MAX_MATCHES:
                break
        if len(matches) >= _GREP_MAX_MATCHES:
            break
    truncated = len(matches) >= _GREP_MAX_MATCHES
    return {
        "status": "ok",
        "verb": "grep",
        "summary": (
            f"{len(matches)} match(es) in {len(set(m['file'] for m in matches))} "
            f"file(s) — {files_scanned} file(s) scanned, {files_skipped} skipped "
            f"(non-text/ext), pattern {pattern!r}"
        ),
        "matches": matches,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": (
            f"match cap {_GREP_MAX_MATCHES} reached — narrow pattern/glob"
            if truncated else None
        ),
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'read', path='<match file>') to read context",
            "report_finding to record a hard-coded secret / route / endpoint",
        ],
        "delta": f"{len(matches)} grep hits",
    }


def _verb_read(target: str, path: Optional[str]) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "read",
            f"no decompiled workspace — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first (or 'class' for a single class)",
        )
    safe = _safe_ws_child(ws, path or "")
    if safe is None:
        return _err_verb(
            target, "read",
            f"path {path!r} refuses containment (no absolute paths, no '..') — "
            f"use a path relative to the workspace, e.g. 'sources/com/pkg/Main.java'",
        )
    if not os.path.isfile(safe):
        return _err_verb(
            target, "read",
            f"path {path!r} not found in workspace — run_jadx('"
            f"{os.path.basename(target)}', 'tree') to list files",
        )
    with open(safe, "rb") as fh:
        blob = fh.read(_OUTPUT_CAP + 1)
    truncated = len(blob) > _OUTPUT_CAP
    text = blob[:_OUTPUT_CAP].decode("utf-8", errors="replace")
    lines = text.count("\n") + 1
    return {
        "status": "ok",
        "verb": "read",
        "summary": f"{path}: {lines} line(s), {len(blob)} byte(s)",
        "output": text,
        "path": os.path.relpath(safe, os.path.realpath(ws)),
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": _TRUNCATION_NOTE if truncated else None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "grep the workspace for what this code references",
            "report_finding to record a discovered artifact",
        ],
        "delta": f"read {path}",
    }


def _verb_tree(target: str, glob: Optional[str]) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "tree",
            f"no decompiled workspace — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first",
        )
    if glob is not None and not _GLOB_RE.match(glob):
        return _err_verb(
            target, "tree",
            f"glob {glob!r} contains characters outside [A-Za-z0-9_*?.-/]; rejected",
        )
    import fnmatch
    all_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            all_files.append(os.path.relpath(os.path.join(dirpath, fname), ws))
    all_files.sort()
    if glob:
        import fnmatch as _fm
        all_files = [f for f in all_files if _fm.fnmatch(f, glob)]
    listing = all_files[:_TREE_LIST_CAP]
    truncated = len(all_files) > _TREE_LIST_CAP
    return {
        "status": "ok",
        "verb": "tree",
        "summary": f"{len(all_files)} file(s) in workspace (showing {len(listing)})",
        "files": listing,
        "total_files": len(all_files),
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": (
            f"listing capped at {_TREE_LIST_CAP} — narrow with glob"
            if truncated else None
        ),
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'read', path='<file from list>')",
            "run_jadx('<name>', 'grep', pattern='<regex>')",
        ],
        "delta": f"listed {len(all_files)} files",
    }


def _count_by_ext(ws: str, ext: str) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        n += sum(1 for f in filenames if f.endswith(ext))
    return n


def _count_all(ws: str, skip: Optional[str] = None) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(ws):
        if skip:
            dirnames[:] = [d for d in dirnames if d != skip]
        else:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        n += len(filenames)
    return n


# ---------------------------------------------------------------------------
# The composite tool
# ---------------------------------------------------------------------------
@framework_tool(
    "Static Android APK analysis with jadx — apk disassembly and "
    "decompilation: disassemble and decompile an APK/dex/jar/aab/xapk into "
    "readable Java sources, decode AndroidManifest.xml, pull a single class "
    "via --single-class, grep the decompiled apk sources with a regex, read "
    "one decompiled file, or list the tree. This is the apk decompiler / "
    "disassembler for Android reverse engineering. One composite tool — "
    "pass a verb (decompile, manifest, class, grep, read, tree) from the "
    "allowlist plus verb-specific params. Targets auto-resolve by bare name "
    "from the apk/ drop folder. Runs offline (no network, no scope gate); "
    "the decompile is cached per target and reused until the apk changes.",
    next_hints=["report_finding"],
)
def run_jadx(
    target: str,
    command: str,
    # --- decompile verb params ---
    deobf: bool = False,
    show_bad_code: bool = False,
    mode: str = "auto",
    threads: Optional[int] = None,
    no_res: bool = False,
    force: bool = False,
    # --- class verb param ---
    single_class: Optional[str] = None,
    # --- grep verb params ---
    pattern: Optional[str] = None,
    glob: Optional[str] = None,
    case_insensitive: bool = False,
    # --- read verb param ---
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Drive jadx against a target from the apk drop folder.

    Args:
        target: Path or bare name resolved against the apk drop folder
            (default ``apk/``; override via ``JADX_APK_TARGETS_ROOT``).
        command: Verb from the frozen allowlist — ``decompile``, ``manifest``,
            ``class``, ``grep``, ``read``, ``tree`` (exact match only).
        deobf: decompile verb — add ``--deobf`` (rename obfuscated classes).
        show_bad_code: decompile verb — add ``--show-bad-code`` (keep
            inconsistent code instead of jadx's comment placeholders).
        mode: decompile verb — ``auto`` (default) | ``restructure`` |
            ``simple`` | ``fallback``.
        threads: decompile verb — ``-j`` thread count, clamped 1..16.
        no_res: decompile verb — add ``-r`` (skip resource decode).
        force: decompile verb — re-run even when the cached workspace is
            fingerprint-fresh.
        single_class: class verb — full class name (``com.example.Foo``;
            inner classes use ``$``).
        pattern: grep verb — Python regex, compiled in-process (never shell).
        glob: grep/tree verb — fnmatch filter on workspace-relative paths.
        case_insensitive: grep verb — regex flag.
        path: read verb — workspace-relative file path (traversal-guarded).

    Returns:
        Dict envelope: ``status, verb, summary, workspace, target,
        jadx_version, output/truncated/truncation_policy, next_hints, delta``
        plus verb-specific fields; errors return ``status="error"`` with an
        ``error`` message instead of raising.
    """
    # --- Layer 1: exact verb allowlist ---
    if command not in _VERB_TABLE:
        return _err_verb(
            target, command,
            f"verb {command!r} is not in the allowlist "
            f"({', '.join(ALLOWED_VERBS)}); rejected",
        )
    if mode not in _DECOMPILE_MODES:
        return _err_verb(
            target, command,
            f"mode {mode!r} not in {', '.join(_DECOMPILE_MODES)}; rejected",
        )
    threads_val: Optional[int] = None
    if threads is not None:
        try:
            threads_val = int(threads)
        except (TypeError, ValueError):
            return _err_verb(target, command, f"threads must be an integer, got {threads!r}")
        threads_val = max(_THREADS_MIN, min(_THREADS_MAX, threads_val))

    # --- target resolution: existing path, or drop-folder auto-resolve ---
    resolved = resolve_apk_target(target) if target else None
    if resolved is None:
        return _err_verb(
            target, command,
            f"target {target!r} not found — no such file, and no match in the "
            f"apk drop folder ({APK_TARGETS_ROOT}). Call list_apk_targets to "
            f"see what is available.",
        )
    target = resolved

    if command == "decompile":
        return _verb_decompile(
            target, bool(deobf), bool(show_bad_code), mode,
            threads_val, bool(no_res), bool(force),
        )
    if command == "manifest":
        return _verb_manifest(target)
    if command == "class":
        return _verb_class(target, single_class)
    if command == "grep":
        return _verb_grep(target, pattern, glob, bool(case_insensitive))
    if command == "read":
        return _verb_read(target, path)
    if command == "tree":
        return _verb_tree(target, glob)
    return _err_verb(target, command, "unreachable verb dispatch")  # belt+braces


def _err_verb(
    target: Optional[str], command: Optional[str], error: str
) -> Dict[str, Any]:
    """Consistent error envelope."""
    return {
        "status": "error",
        "verb": command,
        "summary": error,
        "output": "",
        "workspace": None,
        "truncated": False,
        "truncation_policy": None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [],
        "delta": "",
        "error": error,
    }