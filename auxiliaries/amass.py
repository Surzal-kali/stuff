"""OWASP Amass v5 wrapper — subdomain enumeration via background job + poll.

Passive by default (amass v5's default mode).  Active, brute-force, and
alteration modes are opt-in via the ``options`` string with a flag allowlist.

This module mirrors the proven nmap ``run_nmap`` / ``nmap_status`` shape
using the shared :mod:`utils.background_job` helper:

- ``run_amass(target, options)`` launches ``amass enum`` as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id``.  The
  secretary turn is NOT held open.
- ``amass_status(job_id)`` polls the job.  When the enum is done, it
  retrieves discovered names via ``amass subs -names -show`` (v5's
  retrieval path), falls back to a direct crt.sh CT-log HTTP query if
  amass found nothing, and optionally filters against program scope.
- ``subdomain_enum(target, options)`` is the composite launcher (same
  background job, marks the job for alive-check + structured output).
- ``subdomain_enum_status(job_id)`` polls, retrieves names, does scope
  filtering + DNS alive-check, and returns structured JSON.

amass v5 output model (v5.1+):
  Unlike v4, ``amass enum`` does NOT print subdomain names to stdout.
  stdout only gets a summary header ("Session Scope / FQDN: / <domain>").
  Results live in the engine's SQLite DB and session logs.  The correct
  retrieval path is:
    1. ``amass enum -d <domain> -dir <tmpdir>``  (writes session log + DB)
    2. ``amass subs -names -show -d <domain> -dir <tmpdir>``  (prints names)
  This wrapper automates both steps.  A crt.sh HTTP fallback is layered on
  top because the engine's crt.sh plugin depends on crt.sh being up, and
  crt.sh is frequently overloaded (502).
"""

from __future__ import annotations

import json
import os
import shutil
import shlex
import socket
import subprocess
import tempfile
import threading
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.background_job import launch_job, poll_job

# --- flag allowlist ----------------------------------------------------------

# Boolean flags (no value consumed).  These are safe to let the model toggle.
_BOOL_FLAGS = {
    "-active",       # zone transfers + certificate name grabs
    "-brute",        # DNS brute forcing
    "-alts",         # alteration/permutation generation
    "-norecursive",  # disable recursive brute forcing
    "-rigid",        # disable scope expansion
    "-nocolor",      # disable ANSI codes (always added by wrapper)
    "-demo",         # censor output for demos
    "-passive",      # deprecated in v5 (passive is default) but harmless
    "-silent",       # disable all output during execution
    "-v",            # verbose status / debug / troubleshooting info
}

# Flags that consume the next argv element as a value.
_VALUE_FLAGS = {
    "-w",                # wordlist path for brute forcing
    "-aw",               # wordlist path for alterations
    "-r",                # DNS resolver IPs
    "-rf",               # DNS resolver file
    "-timeout",          # minutes (amass uses minutes, not seconds)
    "-max-depth",        # max subdomain label depth for brute forcing
    "-min-for-recursive",  # labels before recursive brute forcing
    "-include",          # data source names to include
    "-exclude",          # data source names to exclude
    "-p",                # ports (comma-separated)
    "-bl",               # blacklisted subdomain names
    "-blf",              # blacklisted subdomains file
    "-nf",               # already-known subdomains file
    "-awm",              # hashcat-style wordlist masks for alterations
    "-wm",               # hashcat-style wordlist masks for brute forcing
    "-iface",            # network interface
    # --- v5-only value flags ---
    "-config",           # path to YAML configuration file
    "-oA",               # path prefix for naming all output files
    "-log",              # path to log file for errors
    "-df",               # path to file providing root domain names
    "-d",                # domain names (comma-separated, repeatable)
    "-tr",               # trusted DNS resolver IPs
    # NOTE: -dir is managed internally by the wrapper (temp dir for v5
    # output retrieval).  Not exposed to the model to avoid clobbering.
}


def _validate_options(options: str) -> List[str]:
    """Parse and validate an options string against the flag allowlist.

    Returns a clean argv list.  Raises ValueError on disallowed flags.
    """
    if not options or not options.strip():
        return []
    tokens = shlex.split(options)
    clean: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _BOOL_FLAGS:
            clean.append(tok)
            i += 1
        elif tok in _VALUE_FLAGS:
            clean.append(tok)
            if i + 1 < len(tokens):
                clean.append(tokens[i + 1])
                i += 2
            else:
                raise ValueError(f"flag {tok} requires a value")
        else:
            raise ValueError(
                f"disallowed amass flag: {tok!r}. "
                f"Allowed: {sorted(_BOOL_FLAGS | _VALUE_FLAGS)}"
            )
    return clean


# --- amass v5 helpers --------------------------------------------------------

# Extra per-job metadata that launch_job/poll_job don't carry (domain,
# temp output dir, whether to do alive-check).  Keyed by job_id, capped.
_AMASS_JOBS: "Dict[str, Dict[str, Any]]" = {}
_AMASS_LOCK = threading.Lock()
_MAX_AMASS_JOBS = 64


def _retrieve_names(domain: str, out_dir: str) -> List[str]:
    """Retrieve discovered subdomain names from the engine via ``amass subs``.

    In amass v5, ``amass enum`` does NOT print names to stdout.  Results are
    stored in the engine's DB / session log inside ``out_dir``.  This runs
    ``amass subs -names -show -d <domain> -dir <out_dir>`` to pull them out.
    """
    subs_cmd = [
        "amass", "subs",
        "-d", domain,
        "-names",
        "-show",
        "-dir", out_dir,
    ]
    # A big-domain enum (crypto.com-scale) ingests tens of thousands of names
    # over hours; the `amass subs` dump of that DB takes MINUTES. The naive
    # 30s timeout swallowed entire multi-hour runs' results (Sept 11: 2.5h
    # enum -> 0 names reported, timeout eaten by a bare except). Env-tunable
    # timeout + one retry before falling through to crt.sh.
    timeout = float(os.getenv("AMASS_RETRIEVAL_TIMEOUT", "600"))
    for _attempt in (1, 2):
        try:
            result = subprocess.run(
                subs_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            names = [
                line.strip().lower().rstrip(".")
                for line in (result.stdout or "").splitlines()
                if line.strip() and "." in line.strip()
            ]
            return sorted(set(names))
        except subprocess.TimeoutExpired:
            continue  # one retry; a warm-DB second pass often gets through
        except Exception:
            return []
    return []


def _crtsh_fallback(domain: str) -> List[str]:
    """Query crt.sh CT logs directly when amass finds nothing.

    crt.sh is frequently overloaded (502/timeout), so this is best-effort
    with a generous timeout and a single retry.  Returns a sorted list of
    unique subdomain names that are the domain or a subdomain of it
    (wildcard certs stripped).
    """
    domain = domain.lower().rstrip(".")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "amass-wrapper/1.0"})
            with urllib.request.urlopen(
                req, timeout=float(os.getenv("AMASS_CRTSH_TIMEOUT", "120"))
            ) as resp:
                if resp.status != 200:
                    continue
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            names: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().rstrip(".")
                    if name and (name == domain or name.endswith("." + domain)):
                        if not name.startswith("*."):
                            names.add(name)
            return sorted(names)
        except Exception:
            continue
    return []


def _get_names(domain: str, out_dir: str) -> List[str]:
    """Retrieve names from amass v5, falling back to crt.sh if empty.

    This is the shared post-processing step called by both ``amass_status``
    and ``subdomain_enum_status`` once the ``amass enum`` subprocess has
    finished.
    """
    names = _retrieve_names(domain, out_dir)
    if not names:
        names = _crtsh_fallback(domain)
    return names


def _store_amass_meta(job_id: str, domain: str, out_dir: str,
                      options: str, composite: bool) -> None:
    """Stash extra metadata for a launched amass job."""
    with _AMASS_LOCK:
        _AMASS_JOBS[job_id] = {
            "domain": domain,
            "out_dir": out_dir,
            "options": options,
            "composite": composite,
            "result": None,       # cached retrieval result (set on first done-poll)
            "retrieved": False,
        }
        if len(_AMASS_JOBS) > _MAX_AMASS_JOBS:
            # Evict oldest entries that have been retrieved.
            done = sorted(
                (k for k, v in _AMASS_JOBS.items() if v["retrieved"]),
                key=lambda k: _AMASS_JOBS[k].get("started", 0),
            )
            for k in done[: len(_AMASS_JOBS) - _MAX_AMASS_JOBS]:
                meta = _AMASS_JOBS.pop(k)
                try:
                    shutil.rmtree(meta["out_dir"], ignore_errors=True)
                except Exception:
                    pass


def _get_amass_meta(job_id: str) -> Optional[Dict[str, Any]]:
    with _AMASS_LOCK:
        return _AMASS_JOBS.get(job_id)


# --- run_amass (async launcher) + amass_status (poller) ---------------------

@framework_tool(
    "Launch OWASP Amass v5 subdomain enumeration against a domain in the "
    "background. PASSIVE by default (no traffic to target). Add '-active' "
    "for zone transfers and cert grabs, '-brute' for DNS brute forcing, "
    "'-alts' for permutation generation. Non-blocking — starts the scan "
    "and returns immediately with a job_id. Poll with amass_status(job_id) "
    "until status == 'done'. Allowed flags: -active, -brute, -alts, "
    "-norecursive, -rigid, -w <wordlist>, -timeout <minutes>, "
    "-include <sources>, -exclude <sources>, -max-depth <n>, -p <ports>.",
    next_hints=["amass_status", "subdomain_enum (structured result with alive check)"],
)
def run_amass(target, options=""):
    """Launch amass enum against a domain and return immediately.

    amass runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan.  Poll the result with
    ``amass_status(job_id)`` until it reports ``status: "done"``.

    In amass v5, the enum subprocess does NOT print names to stdout.  The
    status function handles v5 retrieval (``amass subs -names``) and crt.sh
    fallback after the enum finishes.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (validated against an allowlist).
                 Passive by default; add '-active', '-brute', '-alts' as needed.
    """
    validated = _validate_options(options)

    # Filter out -dir/-d/-oA from user options — we manage those internally.
    user_flags = []
    skip_next = False
    for tok in validated:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-dir", "-d", "-oA"):
            skip_next = True
            continue
        user_flags.append(tok)

    out_dir = tempfile.mkdtemp(prefix="amass_v5_")
    command = [
        "amass", "enum",
        "-d", target,
        "-nocolor",
        "-dir", out_dir,
        *user_flags,
    ]

    dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
    amass_cap = min(600, dispatch_timeout - 10)

    job = launch_job(
        command,
        tool_name="amass",
        timeout=amass_cap,
    )
    job_id = job["job_id"]
    _store_amass_meta(job_id, target, out_dir, options, composite=False)

    return {
        "job_id": job_id,
        "status": "running",
        "target": target,
        "message": "poll with amass_status(job_id) until status == 'done'",
    }


@framework_tool(
    "Poll an amass enum job: returns running/done, discovered subdomain "
    "names (retrieved via amass v5's subs command + crt.sh fallback), and "
    "scope-filtered results if a .scope file exists. Call until status "
    "reports done.",
    next_hints=["subdomain_enum", "run_nmap -iL <subdomains>"],
)
def amass_status(job_id):
    """Poll the status of an amass enum launched by ``run_amass``.

    When the enum subprocess finishes, this retrieves discovered names via
    ``amass subs -names -show`` (amass v5's retrieval path), falls back to
    a direct crt.sh CT-log query if amass found nothing, and filters against
    the program scope (``.scope`` file) if one exists.

    Args:
        job_id: The ``job_id`` returned by ``run_amass``.
    """
    meta = _get_amass_meta(job_id)
    if meta is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no amass job with id {job_id!r} (it may have been evicted)",
        }

    poll = poll_job(job_id, tool_name="amass")
    status = poll.get("status", "unknown")

    if status != "done":
        # Still running — return the poll result as-is.
        return poll

    # --- Job is done: retrieve names (once, cache the result) ---
    if not meta["retrieved"]:
        domain = meta["domain"]
        names = _get_names(domain, meta["out_dir"])
        with _AMASS_LOCK:
            meta["retrieved"] = True
            meta["result"] = names
    else:
        names = meta["result"]

    # Build the final result.
    if not names:
        result = {
            "job_id": job_id,
            "status": "done",
            "subdomains": [],
            "note": (
                "amass returned no subdomains and crt.sh fallback also "
                "failed (crt.sh may be down — 502/timeout). Possible "
                "causes: crt.sh overloaded, no data-source API keys "
                "configured, or the domain has no CT-log entries. ALSO: on "
                "very large result sets the amass-subs retrieval step may "
                "have timed out even with keys live - the names are still "
                "in the job out_dir (/tmp/amass_v5_* on the framework "
                "host); recover with: amass subs -names -show -d <domain> "
                "-dir <out_dir>."
            ),
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
        }
        return result

    # Scope filtering (same as the old run_amass).
    patterns = _load_scope()
    if patterns is None:
        # Lab mode — no scope file, return raw names.
        return {
            "job_id": job_id,
            "status": "done",
            "subdomains": names,
            "total_discovered": len(names),
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
            "note": "prefer subdomain_enum for alive-checking + structured result",
        }

    in_scope = [s for s in names if _in_scope(s, patterns)]
    out_of_scope = [s for s in names if s not in in_scope]
    return {
        "job_id": job_id,
        "status": "done",
        "subdomains": in_scope,
        "out_of_scope": out_of_scope,
        "total_discovered": len(names),
        "total_in_scope": len(in_scope),
        "elapsed": poll.get("elapsed"),
        "timed_out": poll.get("timed_out", False),
        "note": "prefer subdomain_enum for alive-checking + structured result",
    }


# --- subdomain_enum composite ------------------------------------------------

def _load_scope() -> List[str] | None:
    """Load scope patterns from ``.scope`` in the workspace root.

    Returns None if no scope file exists (lab mode — everything in scope).
    Each line is a scope pattern: ``*.example.com``, ``example.com``, or
    ``api.example.com``.  Lines starting with # are comments.
    """
    scope_file = Path(os.getenv("WORKSPACE_ROOT", ".")) / ".scope"
    if not scope_file.is_file():
        return None
    patterns = []
    for line in scope_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns or None


def _in_scope(subdomain: str, patterns: List[str]) -> bool:
    """Check if a subdomain matches any scope pattern.

    Patterns:
      *.example.com  -> any subdomain of example.com (and example.com itself)
      example.com    -> example.com and any *.example.com
      api.example.com -> exact match only
    """
    sub = subdomain.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat.startswith("*."):
            root = pat[2:]
            if sub == root or sub.endswith("." + root):
                return True
        elif sub == pat or sub.endswith("." + pat):
            return True
    return False


def _is_alive(hostname: str, timeout: float = 3.0) -> bool:
    """DNS-resolve a hostname; return True if it resolves to any A/AAAA record."""
    try:
        socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


def _resolve_alive(
    hostnames: List[str], timeout: float = 3.0, workers: int = 20
) -> List[str]:
    """Concurrently DNS-resolve a list of hostnames.

    Returns the subset that resolve, preserving input order.  Using a
    ThreadPoolExecutor(20) turns 500 subs × 3s worst case from ~25 minutes
    sequential into ~75 seconds.
    """
    alive_set: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_is_alive, h, timeout): h for h in hostnames}
        for future in as_completed(futures):
            if future.result():
                alive_set.add(futures[future])
    return [h for h in hostnames if h in alive_set]


# --- subdomain_enum (async launcher) + subdomain_enum_status (poller) -------

@framework_tool(
    "Launch subdomain enumeration for a domain in the background using "
    "amass, then resolve each discovered subdomain to verify it's alive, "
    "and filter against the program scope (if a .scope file exists). "
    "Non-blocking — starts the scan and returns immediately with a job_id. "
    "Poll with subdomain_enum_status(job_id) until status == 'done' for a "
    "structured JSON result: {subdomains, alive, out_of_scope}. "
    "Passive by default; pass options for active/brute modes.",
    next_hints=["subdomain_enum_status", "run_nmap -iL <alive subdomains>"],
)
def subdomain_enum(target, options=""):
    """Launch amass enum + alive-check composite and return immediately.

    amass runs as a detached background subprocess; this call does NOT block.
    Poll the result with ``subdomain_enum_status(job_id)`` until it reports
    ``status: "done"``.  When done, the status function retrieves names
    (amass v5 ``amass subs`` + crt.sh fallback), filters against program
    scope, and DNS-resolves in-scope subdomains to check if they're alive.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (same allowlist as run_amass).
    """
    validated = _validate_options(options)

    # Filter out -dir/-d/-oA from user options — we manage those internally.
    user_flags = []
    skip_next = False
    for tok in validated:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-dir", "-d", "-oA"):
            skip_next = True
            continue
        user_flags.append(tok)

    out_dir = tempfile.mkdtemp(prefix="amass_v5_")
    command = [
        "amass", "enum",
        "-d", target,
        "-nocolor",
        "-dir", out_dir,
        *user_flags,
    ]

    dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
    amass_cap = min(600, dispatch_timeout - 10)

    job = launch_job(
        command,
        tool_name="amass",
        timeout=amass_cap,
    )
    job_id = job["job_id"]
    _store_amass_meta(job_id, target, out_dir, options, composite=True)

    return {
        "job_id": job_id,
        "status": "running",
        "target": target,
        "message": "poll with subdomain_enum_status(job_id) until status == 'done'",
    }


@framework_tool(
    "Poll a subdomain_enum job: returns running/done plus a structured "
    "JSON result with discovered subdomains, alive (DNS-resolved) hosts, "
    "and out-of-scope names. Call until status reports done.",
    next_hints=["run_nmap -iL <alive subdomains>", "zap_open_url on discovered hosts"],
)
def subdomain_enum_status(job_id):
    """Poll the status of a composite enum launched by ``subdomain_enum``.

    When the amass enum subprocess finishes, this:
    1. Retrieves discovered names (``amass subs -names`` + crt.sh fallback)
    2. Filters against program scope (``.scope`` file) if one exists
    3. DNS-resolves in-scope subdomains to check if they're alive
    4. Returns structured JSON: ``{subdomains, alive, out_of_scope, ...}``

    Args:
        job_id: The ``job_id`` returned by ``subdomain_enum``.
    """
    meta = _get_amass_meta(job_id)
    if meta is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no subdomain_enum job with id {job_id!r} (it may have been evicted)",
        }

    poll = poll_job(job_id, tool_name="amass")
    status = poll.get("status", "unknown")

    if status != "done":
        # Still running — return the poll result as-is.
        return poll

    # --- Job is done: retrieve names (once, cache the result) ---
    if not meta["retrieved"]:
        domain = meta["domain"]
        names = _get_names(domain, meta["out_dir"])
        with _AMASS_LOCK:
            meta["retrieved"] = True
            meta["result"] = names
    else:
        names = meta["result"]

    if not names:
        return {
            "job_id": job_id,
            "status": "done",
            "subdomains": [],
            "alive": [],
            "out_of_scope": [],
            "total_discovered": 0,
            "total_alive": 0,
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
            "note": (
                "amass returned no subdomains and crt.sh fallback also "
                "failed (crt.sh may be down — 502/timeout). Possible "
                "causes: crt.sh overloaded, no data-source API keys "
                "configured, or the domain has no CT-log entries. ALSO: on "
                "very large result sets the amass-subs retrieval step may "
                "have timed out even with keys live - the names are still "
                "in the job out_dir (/tmp/amass_v5_* on the framework "
                "host); recover with: amass subs -names -show -d <domain> "
                "-dir <out_dir>."
            ),
        }

    # Scope filtering.
    patterns = _load_scope()
    if patterns is None:
        in_scope = names
        out_of_scope = []
    else:
        in_scope = [s for s in names if _in_scope(s, patterns)]
        out_of_scope = [s for s in names if s not in in_scope]

    # DNS resolution (alive check) — only on in-scope subs.
    alive = _resolve_alive(in_scope)

    return {
        "job_id": job_id,
        "status": "done",
        "subdomains": in_scope,
        "alive": alive,
        "out_of_scope": out_of_scope,
        "total_discovered": len(names),
        "total_in_scope": len(in_scope),
        "total_alive": len(alive),
        "elapsed": poll.get("elapsed"),
        "timed_out": poll.get("timed_out", False),
    }
