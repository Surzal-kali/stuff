"""OWASP Amass v5 wrapper — subdomain enumeration via subprocess.

Passive by default (amass v5's default mode).  Active, brute-force, and
alteration modes are opt-in via the ``options`` string with a flag allowlist.

Also provides ``subdomain_enum``, a composite tool that runs amass, resolves
discovered subdomains to check if they're alive, and filters against a scope
file (``.scope`` in the workspace root) if one exists.
"""

import json
import os
import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List

from constants import framework_tool

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


# --- amass wrapper (raw) -----------------------------------------------------

class Amass:
    """Thin subprocess wrapper around ``amass enum``."""

    def __init__(self, domain: str):
        self.domain = domain

    def enum(self, options: str = "") -> str:
        validated = _validate_options(options)
        command = [
            "amass", "enum",
            "-d", self.domain,
            "-nocolor",
            *validated,
        ]
        # Cap below the harness BRAIN_DISPATCH_TIMEOUT so the harness net
        # doesn't kill the call before amass's own timeout fires and we get
        # a chance to return partial results.  Default 590s leaves a 10s
        # margin under the harness default of 600s.  The model can pass
        # -timeout N (minutes) to shorten amass's own run further.
        dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
        amass_cap = min(600, dispatch_timeout - 10)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=amass_cap,
            )
            # stdout = subdomain names (one per line); stderr = progress bar.
            # Return stdout, falling back to stderr if empty (error messages).
            return result.stdout or result.stderr
        except subprocess.TimeoutExpired as e:
            # On timeout, e.stdout/e.stderr hold whatever was captured before
            # the kill (populated because capture_output=True).  Return partial
            # results so the composite doesn't die with an uncaught exception.
            partial = (e.stdout or "") or (e.stderr or "")
            return partial or "amass timed out with no output"


@framework_tool(
    "Run OWASP Amass v5 subdomain enumeration against a domain. "
    "PASSIVE by default (no traffic to target). Add '-active' for zone "
    "transfers and cert grabs, '-brute' for DNS brute forcing, '-alts' for "
    "permutation generation. Returns subdomain names, one per line. "
    "Allowed flags: -active, -brute, -alts, -norecursive, -rigid, "
    "-w <wordlist>, -timeout <minutes>, -include <sources>, "
    "-exclude <sources>, -max-depth <n>, -p <ports>.",
    next_hints=["subdomain_enum (structured result with alive check + scope filter)"],
)
def run_amass(target, options=""):
    """Run amass enum against a domain, filtered against program scope.

    If a ``.scope`` file exists in the workspace, results are split into
    in-scope and out-of_scope and returned as JSON.  In lab mode (no scope
    file) raw amass output is returned as-is.  For alive-checking and a
    richer structured result, prefer ``subdomain_enum``.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (validated against an allowlist).
                 Passive by default; add '-active', '-brute', '-alts' as needed.
    """
    amass = Amass(target)
    raw = amass.enum(options)

    # Parse subdomains from stdout (same logic as subdomain_enum)
    subdomains = sorted({
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and "." in line.strip() and not line.strip().startswith("[")
    })

    patterns = _load_scope()
    if patterns is None:
        # Lab mode — no scope file, return raw output
        return raw

    in_scope = [s for s in subdomains if _in_scope(s, patterns)]
    out_of_scope = [s for s in subdomains if s not in in_scope]
    return json.dumps({
        "subdomains": in_scope,
        "out_of_scope": out_of_scope,
        "total_discovered": len(subdomains),
        "note": "prefer subdomain_enum for alive-checking + structured result",
    }, indent=2)


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


@framework_tool(
    "Enumerate subdomains for a domain using amass, then resolve each to "
    "verify it's alive, and filter against the program scope (if a .scope "
    "file exists in the workspace). Returns a structured JSON object: "
    "{subdomains: [...], alive: [...], out_of_scope: [...]}. "
    "Use this instead of run_amass when you want a structured result ready "
    "for nmap or ZAP. Passive by default; pass options for active/brute modes.",
    next_hints=["run_nmap -iL <alive subdomains>", "zap_open_url on discovered hosts"],
)
def subdomain_enum(target, options=""):
    """Composite: amass enum + DNS resolution + scope filtering.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (same allowlist as run_amass).
    """
    # Step 1: run amass
    amass = Amass(target)
    raw = amass.enum(options)

    # Parse stdout — one subdomain per line, strip noise
    subdomains = sorted({
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and "." in line.strip() and not line.strip().startswith("[")
    })

    if not subdomains:
        return json.dumps({
            "subdomains": [],
            "alive": [],
            "out_of_scope": [],
            "note": "amass returned no subdomains",
        })

    # Step 2: scope filtering
    patterns = _load_scope()
    if patterns is None:
        # Lab mode — no scope file, everything in scope
        in_scope = subdomains
        out_of_scope = []
    else:
        in_scope = [s for s in subdomains if _in_scope(s, patterns)]
        out_of_scope = [s for s in subdomains if s not in in_scope]

    # Step 3: DNS resolution (alive check) — only on in-scope subs
    alive = _resolve_alive(in_scope)

    return json.dumps({
        "subdomains": in_scope,
        "alive": alive,
        "out_of_scope": out_of_scope,
        "total_discovered": len(subdomains),
        "total_in_scope": len(in_scope),
        "total_alive": len(alive),
    }, indent=2)
