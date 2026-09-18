"""File-backed, operator-armed scope gate for all traffic-sending tools.

Scope enforcement so a mis-targeted scan or crafted packet can't drift onto
an out-of-scope host.  Arming and disarming is a HUMAN authority action
performed from the Tool REPL (``scope on`` / ``scope off``) — it is
deliberately NOT exposed as an ``@framework_tool``, so the secretary agent
has no way to toggle or circumvent it.  When armed, every traffic-sending
tool consults this gate before firing; when disarmed (the default —
lab / VPN-practice mode) tools behave exactly as before.

Coverage
--------
Two entry points, both consulted before any wire traffic:

* :func:`check_send`  — packetcraft ``send_packet`` (a single destination IP
  extracted from a crafted packet; broadcast/multicast/loopback/link-local
  are never gated).
* :func:`check_scan`   — nmap / masscan / ffuf / hydra / ZAP open/spider/
  ajax/active-scan / send_raw.  Handles URL, bare hostname, IP, CIDR,
  hyphen-range, and whitespace/comma-separated lists.

Why file-backed, not a process singleton
----------------------------------------
The Brain sidecar and the Tool REPL are separate processes.  A tool call
dispatches to the Brain (the agent's normal path) when its socket is up and
falls back in-process otherwise.  A process-global singleton would only gate
the process that armed it.  The armed state is therefore persisted to
``scope/.armed_packet_scope.json`` so the operator's blessing — written from
the REPL — is authoritative in *every* process, including the Brain.  The
file is mtime-checked on each call so a REPL change takes effect immediately
inside a running Brain.  The agent has no tool that writes this file, so it
cannot disarm the gate.

IP <-> hostname bridge
----------------------
Bug-bounty manifests are almost entirely domain/wildcard/URL assets (~0
IP/CIDR across the cached set), but scanners and packet tools operate on
raw IPs/hosts.  The per-target verdict resolves in these tiers, first match
wins (out-of-scope always wins over an in-scope wildcard, mirroring
``program_scope.check_scope``):

1. **Operator allowlist** — IPs the operator blessed via ``scope add-ip``
   (authoritative and CDN-safe: the operator confirmed the IP by
   forward-resolving an in-scope hostname during recon).  This is the
   "passive OSINT allowlist" path.
2. **Manifest match** — :func:`auxiliaries.program_scope._find_match` against
   in-scope assets (DOMAIN/WILDCARD/URL for a hostname, CIDR/IP for an IP).
3. **Reverse-DNS attribution** (IPs only) — PTR-lookup and match the
   resulting hostname(s) against the manifest.  CDN-hosted assets commonly
   PTR to the CDN, not the program domain, so this can false-negative; the
   operator falls back to tier 1 (``scope add-ip``) for those.

Broad ranges (CIDR wider than /32, hyphen-ranges) can't be reliably
attributed host-by-host, so when armed they are allowed ONLY if the network
is a subnet of an explicit in-scope CIDR asset; otherwise they are refused
(broad subnet scanning is not a bug-bounty pattern — disarm for lab /
internal-network work).

If no tier confirms in-scope and ``strict`` is True (default), the action
is REFUSED with guidance ("nada").  ``strict=False`` allows with a warning.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_STATE_PATH = Path(os.getenv("WORKSPACE_ROOT", ".")) / "scope" / ".armed_packet_scope.json"


class ScopeGateError(Exception):
    """Raised by a traffic-sending tool when the scope gate refuses a target.

    Raising (rather than returning an error dict/string) is deliberate: the
    Brain sidecar wraps any non-raising return as outer ``status:"success"``,
    which would bury a scope block as a silent success.  An exception makes
    both dispatch paths (Brain socket + in-process fallback) surface a clean
    ``Failed`` status with the scope reason so the secretary reads it as a
    real failure, not a plausible-success.  ``secretary_execute_tool``
    returns the Failed result to the model (it does not auto-retry), so the
    model can self-correct (different target) or surface the block to the
    operator (bless the IP / disarm).
    """

# In-process mtime cache so a running Brain notices a REPL-side change
# without re-reading the file on every call.  One stat per call is fine for
# scan/packet volumes (dozens, not k/s).
_CACHE: Dict[str, Any] = {"mtime": None, "state": None}


# --------------------------------------------------------------------------- #
# State file I/O
# --------------------------------------------------------------------------- #

def _write_state(state: Dict[str, Any]) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps(state, indent=2))
    _CACHE["mtime"] = _STATE_PATH.stat().st_mtime
    _CACHE["state"] = state


def _load_state() -> Optional[Dict[str, Any]]:
    """Return the armed-state dict, or None when disarmed (no file).

    Mtime-checked so a REPL write is picked up by a separate process (Brain)
    on the very next call without a stale in-memory copy.
    """
    if not _STATE_PATH.is_file():
        _CACHE["mtime"] = None
        _CACHE["state"] = None
        return None
    try:
        mtime = _STATE_PATH.stat().st_mtime
    except OSError:
        return None
    if _CACHE["mtime"] == mtime and _CACHE["state"] is not None:
        return _CACHE["state"]
    try:
        state = json.loads(_STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    _CACHE["mtime"] = mtime
    _CACHE["state"] = state
    return state


def _load_manifest(handle: str, platform: str) -> Optional[Dict[str, Any]]:
    """Lazy import + cache load — keeps program_scope (and its deps) out of
    every importer's module load time."""
    from auxiliaries.program_scope import _load_cache
    return _load_cache(handle, platform)


# --------------------------------------------------------------------------- #
# Small host/IP shape helpers
# --------------------------------------------------------------------------- #

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


def _is_hyphen_range(s: str) -> bool:
    """nmap/masscan 'a.b.c.d-50' or 'a.b.c.d-a.b.c.e' style ranges."""
    if "-" not in s or "/" in s or "://" in s:
        return False
    # Must look numeric-ish on both sides of the (last) dash; reject obvious
    # hostnames like 'co-uk' by requiring digits around the dash.
    parts = s.rsplit("-", 1)
    if len(parts) != 2:
        return False
    left, right = parts
    return bool(re.search(r"\d", left)) and (
        right.isdigit() or re.search(r"\d", right)
    )


def _reverse_dns(ip: str, timeout: float = 2.0) -> List[str]:
    """PTR-lookup an IP, returning lowercased hostnames.  Capped at 2s so a
    slow/broken resolver never pins a scan.  Failure → empty list, which the
    gate treats as 'unconfirmed'."""
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            host, aliases, _ = fut.result(timeout=timeout)
        names = [host.lower()] + [a.lower() for a in (aliases or [])]
        return [n for n in names if n]
    except Exception:
        return []


def _is_gated_target(ip: str) -> bool:
    """True only for routable unicast IPs directed at a real host.  Loopback,
    link-local, multicast, broadcast/reserved, and unspecified addresses are
    local-network traffic, not bounty-host probes — never gate them."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False  # not an IP at all (e.g. a bare MAC) — can't gate
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


# --------------------------------------------------------------------------- #
# Per-target verdict (shared by check_send and check_scan)
# --------------------------------------------------------------------------- #

def _check_one(checkable: Optional[str], state: Dict[str, Any]) -> Tuple[bool, str]:
    """Verdict for a single hostname or IP against the armed scope.

    ``checkable`` may be ``None`` (unparseable) — refused under strict,
    allowed (non-gated) under non-strict so the tool's own validation runs.
    """
    handle = state.get("handle", "")
    platform = state.get("platform", "h1")
    strict = state.get("strict", True)

    if checkable is None:
        if strict:
            return (
                False,
                "target could not be resolved to a checkable host/IP; "
                "refused (strict). Disarm with 'scope off' for lab, or pass "
                "an explicit hostname/IP.",
            )
        return True, "unparseable target (non-strict); not gated"

    checkable = checkable.strip()

    # Tier 1: operator-blessed allowlist (IPs; authoritative, CDN-safe).
    allowlist: Dict[str, str] = state.get("allowlist") or {}
    if checkable in allowlist:
        host = allowlist.get(checkable) or ""
        return True, f"in operator allowlist ({host})" if host else "in operator allowlist"

    manifest = _load_manifest(handle, platform)
    if manifest is None:
        return (
            False,
            f"scope armed for {handle!r}/{platform} but manifest not loadable; "
            f"refusing. Run 'scope off' to disarm, or reload the program scope.",
        )

    from auxiliaries.program_scope import _find_match

    in_assets = manifest.get("in_scope", [])
    out_assets = manifest.get("out_of_scope_assets", [])

    # OOS always wins over a wildcard.
    if _find_match(checkable, out_assets):
        return False, f"{checkable} matches an explicitly out-of-scope asset; refused"

    # Tier 2: manifest match (domain/wildcard/URL for a hostname; CIDR/IP for an IP).
    if _find_match(checkable, in_assets):
        return True, f"{checkable} matches an in-scope asset"

    # Tier 3: reverse-DNS attribution (IPs only).
    if _is_ip(checkable):
        for host in _reverse_dns(checkable):
            if _find_match(host, out_assets):
                return False, f"reverse-DNS {host} (for {checkable}) matches an out-of-scope asset; refused"
            if _find_match(host, in_assets):
                return True, f"reverse-DNS {host} (for {checkable}) matches an in-scope asset"

    # Unconfirmed.
    if strict:
        return (
            False,
            f"{checkable} not confirmed in-scope for program {handle!r}; refused "
            f"(strict). Bless it with 'scope add-ip {checkable} <hostname>' in "
            f"the Tool REPL after confirming it belongs to an in-scope host, or "
            f"'scope off' for lab mode.",
        )
    return True, f"WARNING: {checkable} not confirmed in-scope (non-strict); proceeding"


def _check_broad(spec: str, state: Dict[str, Any]) -> Tuple[bool, str]:
    """Verdict for a broad CIDR / hyphen-range target.

    A broad range can't be attributed host-by-host (a /24 reverse-DNS is 256
    lookups).  It is allowed ONLY when it is a subnet of an explicit in-scope
    CIDR asset; otherwise refused under strict — broad subnet scanning is not
    a bug-bounty pattern.  Disarm (``scope off``) for lab / internal-network
    work where broad ranges are legitimate.
    """
    handle = state.get("handle", "")
    platform = state.get("platform", "h1")
    strict = state.get("strict", True)

    if _is_cidr(spec):
        try:
            net = ipaddress.ip_network(spec.strip(), strict=False)
        except ValueError:
            return _check_one(spec, state)  # not actually a CIDR; try as host
        manifest = _load_manifest(handle, platform)
        if manifest is not None:
            from auxiliaries.program_scope import _find_match
            # First: is it explicitly OOS?
            if _find_match(spec.strip(), manifest.get("out_of_scope_assets", [])):
                return False, f"{spec} matches an explicitly out-of-scope asset; refused"
            # Subnet of an in-scope CIDR asset?
            for a in manifest.get("in_scope", []):
                if (a.get("asset_type") or "").upper() in ("CIDR", "IP", "IP_ADDRESS"):
                    ident = (a.get("asset_identifier") or "").strip()
                    try:
                        asset_net = ipaddress.ip_network(ident, strict=False)
                    except ValueError:
                        continue
                    try:
                        if net.subnet_of(asset_net):
                            return True, f"{spec} is within in-scope CIDR asset {ident}"
                    except TypeError:
                        continue  # mixed v4/v6
        if strict:
            return (
                False,
                f"broad range {spec} not confirmable in-scope for {handle!r}; "
                f"refused (strict). Broad subnet scanning is not a bug-bounty "
                f"pattern — 'scope off' for lab/internal work, or scan specific "
                f"in-scope hosts.",
            )
        return True, f"WARNING: broad range {spec} not confirmed in-scope (non-strict)"

    # Hyphen range (not a CIDR): can't check containment reliably.
    if strict:
        return (
            False,
            f"hyphen-range {spec} not checkable against scope; refused (strict). "
            f"'scope off' for lab/internal work, or scan specific in-scope hosts.",
        )
    return True, f"WARNING: range {spec} not confirmed in-scope (non-strict)"


# --------------------------------------------------------------------------- #
# Public verdicts (called by traffic-sending tools)
# --------------------------------------------------------------------------- #

def check_send(dst_ip: Optional[str]) -> Tuple[bool, str]:
    """Verdict for a single packet destination IP (packetcraft).

    ``dst_ip`` is the destination extracted from the crafted packet
    (``pkt[IP].dst`` or ``pkt[ARP].pdst``); ``None`` means the frame carries
    no directed host IP (pure L2) and is allowed.  Non-routable destinations
    (broadcast/multicast/loopback/link-local) are never gated.
    """
    state = _load_state()
    if state is None:
        return True, "no scope armed (lab mode)"
    if dst_ip is None or not _is_gated_target(dst_ip):
        return True, "non-routable/local destination; not scope-gated"
    return _check_one(dst_ip, state)


def check_scan(target: Optional[str]) -> Tuple[bool, str]:
    """Verdict for a scan-tool target (nmap/masscan/ffuf/hydra/ZAP).

    Handles URL, bare hostname, IP, CIDR, hyphen-range, and whitespace/comma
    separated lists.  Refuses the whole scan if ANY spec is out-of-scope or
    unconfirmed (never partially fire).  Empty/None target is refused when
    armed (can't confirm scope for nothing) and allowed when disarmed.
    """
    state = _load_state()
    if state is None:
        return True, "no scope armed (lab mode)"

    raw = (target or "").strip()
    if not raw:
        return (
            False,
            "empty target; cannot confirm scope (scope armed). Pass an "
            "explicit in-scope target, or 'scope off' for lab mode.",
        )

    # Keep a URL whole (it may contain characters that look like separators);
    # otherwise split nmap/masscan-style "host1 host2,10.0.0.0/24" lists.
    if "://" in raw:
        specs = [raw]
    else:
        specs = [s.strip() for s in re.split(r"[\s,]+", raw) if s.strip()]

    for spec in specs:
        checkable, broad = _spec_to_checkable(spec)
        if broad:
            ok, reason = _check_broad(spec, state)
        else:
            ok, reason = _check_one(checkable, state)
        if not ok:
            return False, f"target {spec!r}: {reason}"
    return True, f"all {len(specs)} target spec(s) confirmed in-scope"


def _spec_to_checkable(spec: str) -> Tuple[Optional[str], bool]:
    """Reduce one target spec to a (checkable_hostname_or_ip, is_broad_range).

    ``is_broad_range`` is True for CIDRs wider than /32 and hyphen-ranges,
    which are handled by :func:`_check_broad` instead of host-by-host.
    """
    spec = spec.strip()
    if "://" in spec:
        host = urlparse(spec).hostname
        return (host, False) if host else (None, False)
    if _is_cidr(spec):
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return (spec, False)
        if net.prefixlen in (32, 128):
            return (str(net.network_address), False)
        return (None, True)
    if _is_hyphen_range(spec):
        return (None, True)
    if _is_ip(spec):
        return (spec, False)
    return (spec, False)  # bare hostname


# --------------------------------------------------------------------------- #
# Operator control surface — called from the Tool REPL only (not agent tools)
# --------------------------------------------------------------------------- #

def arm(handle: str, platform: str = "h1", strict: bool = True) -> Dict[str, Any]:
    """Arm the scope gate against a program's manifest.

    Ensures the manifest is cached first (fetches via load_program_scope if
    missing) so the gate has something to match against.  Returns an
    ``{ok, ...}`` summary; ``ok=False`` with an ``error`` when the manifest
    can't be loaded (refuses to arm blind).
    """
    handle = (handle or "").strip()
    platform = (platform or "h1").strip().lower()
    if not handle:
        return {"ok": False, "error": "handle is required: scope on <handle> [--platform ...]"}

    from auxiliaries.program_scope import _load_cache, load_program_scope

    manifest = _load_cache(handle, platform)
    if manifest is None:
        manifest = load_program_scope(handle, refresh=False, platform=platform)
    if not manifest or (
        isinstance(manifest, dict)
        and manifest.get("status") == "error"
        and not manifest.get("in_scope")
    ):
        return {
            "ok": False,
            "error": (
                f"no scope manifest for {handle!r}/{platform}; "
                f"run load_program_scope first (or load_program_scope --refresh)."
            ),
        }

    state = {
        "handle": handle,
        "platform": platform,
        "strict": bool(strict),
        "allowlist": {},
        "armed_at": time.time(),
    }
    _write_state(state)
    return {
        "ok": True,
        "handle": handle,
        "platform": platform,
        "strict": strict,
        "in_scope_assets": len(manifest.get("in_scope", [])),
        "out_of_scope_assets": len(manifest.get("out_of_scope_assets", [])),
        "message": (
            "scope gate ARMED. Traffic-sending tools (nmap/masscan/ffuf/hydra/"
            "ZAP/packetcraft) will refuse out-of-scope targets. Use "
            "'scope add-ip <ip> <hostname>' to bless CDN/resolved IPs, "
            "'scope off' to disarm."
        ),
    }


def disarm() -> Dict[str, Any]:
    """Disarm the gate (lab mode — tools unrestricted)."""
    if _STATE_PATH.exists():
        try:
            _STATE_PATH.unlink()
        except OSError:
            pass
    _CACHE["mtime"] = None
    _CACHE["state"] = None
    return {"ok": True, "disarmed": True, "message": "scope gate DISARMED (lab mode)."}


def add_ip(ip: str, hostname: str = "") -> Dict[str, Any]:
    """Bless an IP into the operator allowlist (authoritative, CDN-safe).

    Use this after confirming via recon (amass/dns forward-resolution) that
    ``ip`` belongs to an in-scope host.  Requires the gate to be armed.
    """
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed; run 'scope on <handle>' first"}
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "ip is required"}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": f"{ip!r} is not a valid IP address"}
    state.setdefault("allowlist", {})[ip] = (hostname or "").strip()
    _write_state(state)
    return {
        "ok": True,
        "ip": ip,
        "hostname": hostname or "",
        "allowlist_size": len(state["allowlist"]),
        "message": f"blessed {ip}" + (f" ({hostname})" if hostname else ""),
    }


def remove_ip(ip: str) -> Dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed"}
    allowlist = state.get("allowlist") or {}
    if ip not in allowlist:
        return {"ok": False, "error": f"{ip} not in allowlist"}
    del allowlist[ip]
    _write_state(state)
    return {"ok": True, "ip": ip, "allowlist_size": len(allowlist)}


def list_ips() -> Dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "allowlist": {}}
    return {"ok": True, "armed": True, "allowlist": state.get("allowlist") or {}}


def status() -> Dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "message": "disarmed (lab mode — tools unrestricted)"}
    out: Dict[str, Any] = {
        "ok": True,
        "armed": True,
        "handle": state.get("handle"),
        "platform": state.get("platform", "h1"),
        "strict": state.get("strict", True),
        "allowlist_size": len(state.get("allowlist") or {}),
        "armed_at": state.get("armed_at"),
    }
    manifest = _load_manifest(state.get("handle", ""), state.get("platform", "h1"))
    if manifest:
        out["in_scope_assets"] = len(manifest.get("in_scope", []))
        out["out_of_scope_assets"] = len(manifest.get("out_of_scope_assets", []))
    return out


def is_armed() -> bool:
    """Cheap boolean for the REPL prompt indicator (no manifest load)."""
    return _load_state() is not None


__all__ = [
    "check_send",
    "check_scan",
    "ScopeGateError",
    "arm",
    "disarm",
    "add_ip",
    "remove_ip",
    "list_ips",
    "status",
    "is_armed",
]
