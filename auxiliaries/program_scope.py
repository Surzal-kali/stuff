"""HackerOne program scope as a checkable manifest.

Pulls a program's structured scope, scope exclusions, weakness list, and
policy text from the HackerOne Hacker API v1 and turns them into a
machine-readable manifest the secretary model (and the scan tools) can
consult.  This closes two recurring gaps for bug-bounty runs:

* **Scope-compliance enforcement** — ``check_scope(target)`` answers
  "is this host/URL/CIDR/app-id inside the program's authorised assets?"
  *before* a scan tool fires, so a mis-targeted nmap/ffuf/masscan can't
  drift onto a different-org in-scope asset (``og.com``, ``nadex.com``)
  or a genuinely out-of-scope one.  The ``asset_type`` field means
  wildcards, URL hosts, mobile app IDs and blockchain tokens are matched
  correctly rather than treated as bare hostnames.

* **Reportability gate** — ``check_reportable(category_or_cwe)`` tests a
  candidate finding against the program's ``scope_exclusions`` (excluded
  report *categories*, e.g. "missing security headers", "brute force on
  rate-limited logins") and the reportable ``weaknesses`` allowlist, so
  the secretary doesn't burn HackerOne reputation filing N/A/spam-grade
  reports.  ``program_hacktivity`` adds a dedup check against already-
  disclosed reports for the program.

On load, the in-scope DOMAIN/WILDCARD/URL assets are also written to the
workspace ``.scope`` file in the format ``auxiliaries.amass._load_scope``
already consumes, so ``subdomain_enum`` auto-filters against the *real*
HackerOne scope with zero extra wiring.

Authentication
--------------
The structured_scopes / scope_exclusions / program / weaknesses endpoints
require a HackerOne API token (Basic auth, ``<username>:<token>``).  Generate
one at hackerone.com → Settings → API Tokens.  Set ``H1_API_USERNAME`` and
``H1_API_TOKEN`` in the environment (or ``.env``).  ``program_hacktivity``
works without credentials (the hacktivity feed is public); the other tools
return a clear ``auth_required`` error if no token is configured.

The manifest is cached to ``.h1_scope_<handle>.json`` under
``WORKSPACE_ROOT``; pass ``refresh=True`` to force a fresh fetch, or rely on
the ``updated_at`` filter for incremental refreshes.
"""

from __future__ import annotations

import ipaddress
import json as _json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from constants import framework_tool

# --- .env loading (sudo-safe) ------------------------------------------------
# When the framework is launched under sudo, the shell environment is stripped
# and .env is never sourced.  Load it here as a module-level safety net so
# H1_API_USERNAME / H1_API_TOKEN (and every other .env var) are available
# regardless of entry point.  python-dotenv only sets vars that are not already
# in os.environ, so explicit shell exports always win.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass  # dotenv not installed or .env missing — silently degrade


_H1_API = "https://api.hackerone.com/v1"
_TIMEOUT = 30.0


# --- credentials ------------------------------------------------------------

def _h1_auth() -> Tuple[Optional[Tuple[str, str]], bool]:
    """Return ((username, token), has_full_auth) for requests auth.

    ``has_full_auth`` is True only when both env vars are set — the
    structured-scope endpoints need it; hacktivity does not.
    """
    user = os.getenv("H1_API_USERNAME")
    token = os.getenv("H1_API_TOKEN")
    if user and token:
        return ((user, token), True)
    return (None, False)


def _get(path: str, *, params: Optional[Dict[str, Any]] = None,
         auth: Optional[Any] = ...) -> Tuple[int, Any]:
    """GET against the H1 Hacker API.  Returns (status, json).

    By default (``auth=...`` sentinel) the H1 Basic auth tuple is resolved
    via :func:`_h1_auth` and attached.  Pass ``auth=None`` explicitly to
    make an unauthenticated request (used for the public hacktivity feed,
    so stale/bad credentials don't poison a public endpoint with a 401).
    """
    import requests

    if auth is ...:
        auth, _ = _h1_auth()
    url = f"{_H1_API}{path}"
    r = requests.get(url, params=params, auth=auth, headers={"Accept": "application/json"},
                     timeout=_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return (r.status_code, body)


# --- paginated fetch --------------------------------------------------------

def _fetch_all_pages(path: str, *, params: Optional[Dict[str, Any]] = None,
                     max_pages: int = 100) -> Tuple[int, List[Dict[str, Any]], Optional[str]]:
    """Follow pagination links for a list endpoint.

    Returns (status, items, error).  H1 list endpoints wrap items in
    ``data`` and expose ``links.next``.  We also fall back to incrementing
    ``page[number]`` when ``links.next`` is absent.
    """
    params = dict(params or {})
    if "page[size]" not in params:
        params["page[size]"] = 100
    page = int(params.get("page[number]", 1))
    items: List[Dict[str, Any]] = []
    for _ in range(max_pages):
        params["page[number]"] = page
        status, body = _get(path, params=params)
        if status != 200 or not isinstance(body, dict):
            err = None
            if isinstance(body, dict) and body.get("errors"):
                err = str(body["errors"])
            return (status, items, err or f"HTTP {status}")
        data = body.get("data")
        if isinstance(data, list):
            items.extend(data)
        links = body.get("links") or {}
        nxt = links.get("next")
        if not nxt:
            # No link header: stop if this page was short, else keep paging.
            if len(data if isinstance(data, list) else []) < int(params["page[size]"]):
                break
            page += 1
            continue
        # Extract page[number] from the next URL if present, else increment.
        m = re.search(r"page%5Bnumber%5D=(\d+)", nxt) or re.search(r"page\[number\]=(\d+)", nxt)
        if m:
            page = int(m.group(1))
        else:
            page += 1
    return (200, items, None)


# --- manifest construction --------------------------------------------------

def _scope_cache_path(handle: str) -> Path:
    return Path(os.getenv("WORKSPACE_ROOT", ".")) / f".h1_scope_{handle}.json"


def _build_manifest(handle: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch all H1 scope data for ``handle`` and assemble the manifest dict."""
    auth, has_auth = _h1_auth()
    if not has_auth:
        return ({}, ("auth_required: set H1_API_USERNAME and H1_API_TOKEN "
                     "(generate at hackerone.com → Settings → API Tokens)"))

    # structured scopes (in- AND out-of-scope assets, split by eligible flags)
    st, scopes, err = _fetch_all_pages(f"/hackers/programs/{handle}/structured_scopes")
    if err:
        return ({}, f"structured_scopes: {err}")

    in_scope: List[Dict[str, Any]] = []
    out_of_scope_assets: List[Dict[str, Any]] = []
    for it in scopes:
        a = it.get("attributes", {})
        entry = {
            "id": it.get("id"),
            "asset_type": a.get("asset_type"),
            "asset_identifier": a.get("asset_identifier"),
            "eligible_for_bounty": a.get("eligible_for_bounty"),
            "eligible_for_submission": a.get("eligible_for_submission"),
            "max_severity": a.get("max_severity"),
            "instruction": a.get("instruction"),
            "confidentiality_requirement": a.get("confidentiality_requirement"),
            "integrity_requirement": a.get("integrity_requirement"),
            "availability_requirement": a.get("availability_requirement"),
            "reference": a.get("reference"),
            "updated_at": a.get("updated_at"),
        }
        if a.get("eligible_for_submission"):
            in_scope.append(entry)
        else:
            out_of_scope_assets.append(entry)

    # scope exclusions (excluded report *categories*)
    _, exclusions, _ = _fetch_all_pages(f"/hackers/programs/{handle}/scope_exclusions")
    excluded_categories = [
        {
            "category": e.get("attributes", {}).get("category"),
            "details": e.get("attributes", {}).get("details"),
        }
        for e in exclusions
    ]

    # weaknesses (reportable CWE allowlist)
    _, weaknesses, _ = _fetch_all_pages(f"/hackers/programs/{handle}/weaknesses")
    weakness_list = [
        {
            "id": w.get("id"),
            "name": w.get("attributes", {}).get("name"),
            "external_id": w.get("attributes", {}).get("external_id"),
            "description": w.get("attributes", {}).get("description"),
        }
        for w in weaknesses
    ]

    # program policy text
    pol_status, pol_body = _get(f"/hackers/programs/{handle}")
    policy = ""
    if pol_status == 200 and isinstance(pol_body, dict):
        policy = (pol_body.get("data", {}).get("attributes", {}) or {}).get("policy", "")

    manifest = {
        "handle": handle,
        "fetched_at": time.time(),
        "in_scope": in_scope,
        "out_of_scope_assets": out_of_scope_assets,
        "excluded_categories": excluded_categories,
        "weaknesses": weakness_list,
        "policy": policy,
        "counts": {
            "in_scope": len(in_scope),
            "out_of_scope_assets": len(out_of_scope_assets),
            "excluded_categories": len(excluded_categories),
            "weaknesses": len(weakness_list),
        },
    }
    return (manifest, None)


def _write_scope_file(manifest: Dict[str, Any]) -> Optional[str]:
    """Write amass-compatible ``.scope`` from DOMAIN/WILDCARD/URL assets.

    Returns the path written, or None if nothing applicable.  Format matches
    ``auxiliaries.amass._load_scope``: ``*.example.com`` (wildcard),
    ``example.com`` (domain + subdomains), ``api.example.com`` (exact),
    ``#`` comments.  URL assets are reduced to their host.
    """
    patterns: List[str] = []
    for a in manifest.get("in_scope", []):
        atype = (a.get("asset_type") or "").upper()
        ident = (a.get("asset_identifier") or "").strip()
        if not ident:
            continue
        if atype in ("WILDCARD", "DOMAIN"):
            patterns.append(ident)
        elif atype == "URL":
            host = urlparse(ident if "://" in ident else f"http://{ident}").hostname
            if host:
                patterns.append(host)
    if not patterns:
        return None
    scope_path = Path(os.getenv("WORKSPACE_ROOT", ".")) / ".scope"
    seen = set()
    lines = ["# Auto-generated from HackerOne program scope — do not edit by hand.",
             f"# Source: {manifest.get('handle')} @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(manifest.get('fetched_at', time.time())))}"]
    for p in patterns:
        if p not in seen:
            seen.add(p)
            lines.append(p)
    scope_path.write_text("\n".join(lines) + "\n")
    return str(scope_path)


def _save_cache(handle: str, manifest: Dict[str, Any]) -> str:
    p = _scope_cache_path(handle)
    p.write_text(_json.dumps(manifest, indent=2))
    return str(p)


def _load_cache(handle: str) -> Optional[Dict[str, Any]]:
    p = _scope_cache_path(handle)
    if not p.is_file():
        return None
    try:
        return _json.loads(p.read_text())
    except (OSError, ValueError):
        return None


# --- scope matching ---------------------------------------------------------

def _host_of(target: str) -> str:
    """Extract a bare hostname from a URL/host-ish string."""
    t = target.strip()
    if "://" in t:
        h = urlparse(t).hostname
        return (h or "").lower()
    # strip any :port
    return t.split(":")[0].split("/")[0].lower()


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _match_asset(target: str, asset: Dict[str, Any]) -> bool:
    """Test whether ``target`` falls under one in-scope asset."""
    atype = (asset.get("asset_type") or "").upper()
    ident = (asset.get("asset_identifier") or "").strip()
    if not ident:
        return False
    t = target.strip()

    if atype == "WILDCARD":
        # *.crypto.com  ->  matches crypto.com and any subdomain
        root = ident.lstrip("*.").lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "DOMAIN":
        root = ident.lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "URL":
        host = _host_of(t)
        ahost = _host_of(ident)
        if host != ahost:
            return False
        # if the asset has a path, a URL target under that path is in scope
        apath = urlparse(ident if "://" in ident else f"http://{ident}").path or "/"
        tpath = urlparse(t if "://" in t else f"http://{t}").path or "/"
        if apath in ("/", ""):
            return True
        return tpath == apath or tpath.startswith(apath.rstrip("/") + "/")
    if atype == "CIDR":
        try:
            net = ipaddress.ip_network(ident, strict=False)
            ip = ipaddress.ip_address(_host_of(t) if _is_ip(_host_of(t)) else t)
            return ip in net
        except ValueError:
            return False
    if atype in ("IP", "IP_ADDRESS"):
        try:
            return ipaddress.ip_address(t.strip()) == ipaddress.ip_address(ident)
        except ValueError:
            return False
    if atype in ("ANDROID", "IOS"):
        return t.strip().lower() == ident.lower()
    if atype == "BLOCKCHAIN":
        return ident.lower() in t.lower() or t.lower() in ident.lower()
    # OTHER / unknown: substring match as a last resort
    return ident.lower() in t.lower()


def _find_match(target: str, assets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find the best-matching asset for ``target``.

    Two passes so a specific asset (URL with a path, IP, CIDR, app id,
    blockchain token) wins over a broad WILDCARD/DOMAIN that would also
    match the same host — e.g. ``https://crypto.com/exchange/BTC`` should
    bind to the ``https://crypto.com/exchange`` URL asset (with its own
    max_severity / CIA requirements) rather than to ``*.crypto.com``.
    """
    specific = {"URL", "IP", "IP_ADDRESS", "CIDR", "ANDROID", "IOS", "BLOCKCHAIN", "OTHER"}
    for a in assets:
        if (a.get("asset_type") or "").upper() in specific and _match_asset(target, a):
            return a
    for a in assets:
        if _match_asset(target, a):
            return a
    return None


# --- tools ------------------------------------------------------------------

@framework_tool(
    "Load a HackerOne bug-bounty program's scope as a structured, "
    "checkable manifest: in-scope assets (typed: URL/WILDCARD/DOMAIN/CIDR/"
    "IP/ANDROID/IOS/BLOCKCHAIN with max_severity and CIA requirements), "
    "out-of-scope assets, excluded report categories, the reportable "
    "weakness/CWE allowlist, and the program policy text. Also writes the "
    "workspace .scope file so subdomain_enum auto-filters against the real "
    "HackerOne scope. Cached to disk; pass refresh=True to force a fresh "
    "fetch. Requires H1_API_USERNAME and H1_API_TOKEN in the environment.",
    next_hints=["check_scope", "check_reportable", "subdomain_enum"],
)
def load_program_scope(handle: str = "crypto", refresh: bool = False) -> Dict[str, Any]:
    """Fetch (or load cached) HackerOne program scope for ``handle``.

    Args:
        handle: The HackerOne program handle, e.g. ``"crypto"`` for
            crypto.com.  Defaults to ``"crypto"``.
        refresh: If True, ignore the on-disk cache and fetch fresh from
            the API.  Defaults to False (use cache if present and recent).
    """
    if not refresh:
        cached = _load_cache(handle)
        if cached:
            cached["_cache"] = "hit"
            return cached

    manifest, err = _build_manifest(handle)
    if err:
        # Fall back to cache if the live fetch failed but we have one.
        cached = _load_cache(handle)
        if cached:
            cached["_cache"] = "stale-fallback"
            cached["_warning"] = f"live fetch failed ({err}); serving cached copy"
            return cached
        return {"handle": handle, "status": "error", "error": err}

    _save_cache(handle, manifest)
    scope_path = _write_scope_file(manifest)
    manifest["_cache"] = "miss"
    manifest["scope_file"] = scope_path
    manifest["status"] = "ok"
    return manifest


@framework_tool(
    "Check whether a target (host, URL, IP/CIDR, or mobile app package id) "
    "is inside a HackerOne program's authorised scope. Returns in_scope "
    "True/False, the matched asset (with asset_type, max_severity, CIA "
    "requirements, and any instruction), and a reason. Call this BEFORE "
    "running nmap/masscan/ffuf/ZAP against any target to avoid scanning "
    "out-of-scope or wrong-org assets. Loads the scope manifest first "
    "(from cache or live) if not already loaded.",
    next_hints=["run_nmap", "run_ffuf", "run_masscan", "zap_open_url"],
)
def check_scope(target: str, handle: str = "crypto") -> Dict[str, Any]:
    """Test ``target`` against the loaded scope manifest for ``handle``.

    Args:
        target: A hostname, URL, IP, CIDR, or mobile app package id.
        handle: HackerOne program handle. Defaults to ``"crypto"``.
    """
    manifest = _load_cache(handle)
    if manifest is None:
        manifest = load_program_scope(handle, refresh=False)
    if manifest.get("status") == "error" and not manifest.get("in_scope"):
        return {"target": target, "in_scope": False, "reason": manifest.get("error", "no scope loaded")}

    in_assets = manifest.get("in_scope", [])
    out_assets = manifest.get("out_of_scope_assets", [])
    match = _find_match(target, in_assets)
    if match:
        return {
            "target": target,
            "in_scope": True,
            "matched_asset": match,
            "max_severity": match.get("max_severity"),
            "reason": f"matches in-scope {match.get('asset_type')} asset {match.get('asset_identifier')!r}",
        }
    out_match = _find_match(target, out_assets)
    if out_match:
        return {
            "target": target,
            "in_scope": False,
            "matched_asset": out_match,
            "reason": (f"matches an explicitly out-of-scope asset "
                       f"{out_match.get('asset_identifier')!r}"),
        }
    return {
        "target": target,
        "in_scope": False,
        "reason": "no matching asset in the program scope",
    }


@framework_tool(
    "Check whether a candidate finding is reportable under a HackerOne "
    "program's rules: tests a category name or CWE id against the program's "
    "excluded report categories (scope_exclusions) and the reportable "
    "weakness allowlist. Returns reportable True/False, which exclusion it "
    "hit (if any), and whether the CWE is in the program's weakness list. "
    "Use this as a gate before report_finding to avoid filing N/A or "
    "spam-grade reports that hurt your HackerOne reputation.",
    next_hints=["report_finding", "program_hacktivity"],
)
def check_reportable(category_or_cwe: str, handle: str = "crypto") -> Dict[str, Any]:
    """Test a finding category/CWE against the program's exclusion + weakness rules.

    Args:
        category_or_cwe: A vulnerability category name (e.g. "Missing security
            headers", "Brute force", "Open redirect") or a CWE id
            (e.g. "CWE-89", "cwe-352").  Matched case-insensitively.
        handle: HackerOne program handle. Defaults to ``"crypto"``.
    """
    manifest = _load_cache(handle)
    if manifest is None:
        manifest = load_program_scope(handle, refresh=False)

    needle = category_or_cwe.strip().lower()
    cwe_norm = re.sub(r"[^0-9]", "", needle) if "cwe" in needle else None

    # 1. Excluded categories (scope_exclusions) — a hit means NOT reportable.
    excluded = manifest.get("excluded_categories", [])
    hit_excl = None
    for e in excluded:
        cat = (e.get("category") or "").lower()
        det = (e.get("details") or "").lower()
        if needle in cat or needle in det or cat and cat in needle:
            hit_excl = e
            break

    # 2. Weakness allowlist — is this CWE recognised by the program?
    weaknesses = manifest.get("weaknesses", [])
    weakness_hit = None
    if cwe_norm:
        for w in weaknesses:
            ext = (w.get("external_id") or "")
            if ext and re.sub(r"[^0-9]", "", ext) == cwe_norm:
                weakness_hit = w
                break
    # also try matching by name substring
    if not weakness_hit:
        for w in weaknesses:
            name = (w.get("name") or "").lower()
            if name and needle in name:
                weakness_hit = w
                break

    reportable = not hit_excl
    reason = "no exclusion matched"
    if hit_excl:
        reason = (f"matches excluded category {hit_excl.get('category')!r}: "
                  f"{hit_excl.get('details')}")
    return {
        "category_or_cwe": category_or_cwe,
        "reportable": reportable,
        "exclusion_hit": hit_excl,
        "weakness_match": weakness_hit,
        "reason": reason,
    }


@framework_tool(
    "Fetch a HackerOne program's publicly disclosed reports (hacktivity) "
    "for duplicate-checking before you write up a finding. Works WITHOUT "
    "API credentials (the hacktivity feed is public). Optionally filter "
    "with a Lucene query string (e.g. 'severity_rating:high AND "
    "cwe:SSRF'). Returns a compact list of disclosed report titles, "
    "substates, severity, and URLs so you can avoid filing a dupe.",
    next_hints=["check_reportable", "report_finding"],
)
def program_hacktivity(handle: str = "crypto", query: str = "", limit: int = 25) -> Dict[str, Any]:
    """Fetch disclosed reports for a program (dedup aid).

    Args:
        handle: HackerOne program handle. Defaults to ``"crypto"``.
        query: Optional Lucene filter appended to ``team_handle:<handle>``
            (e.g. ``"severity_rating:high"``).  Empty = all disclosed.
        limit: Max items (1-100). Defaults to 25.
    """
    limit = max(1, min(100, int(limit)))
    qs = f"team_handle:{handle}"
    if query.strip():
        qs += f" AND {query.strip()}"
    status, body = _get("/hackers/hacktivity", params={"queryString": qs, "page[size]": limit},
                        auth=None)
    if status != 200 or not isinstance(body, dict):
        return {"handle": handle, "status": "error", "error": f"HTTP {status}", "reports": []}
    reports = []
    for it in body.get("data", []):
        a = it.get("attributes", {}) or {}
        reports.append({
            "id": it.get("id"),
            "title": a.get("title"),
            "substate": a.get("substate"),
            "severity": a.get("severity_rating"),
            "cwe": a.get("cwe"),
            "url": a.get("url"),
            "disclosed_at": a.get("disclosed_at"),
            "total_awarded": a.get("total_awarded_amount"),
        })
    return {"handle": handle, "status": "ok", "count": len(reports), "reports": reports}
