"""HTTP GET with per-hop scope-gate validation (redirect-bypass blocker).

The bypass this module closes (flagged by the operator 2026-09-19): a
tool validates its entry URL through the scope gate, fires the request,
the target answers 302 — and ``requests`` happily follows to a host the
gate never saw.  Redirects are attacker-controlled routing: a lab host
can 302 the client to an out-of-scope machine and the traffic fires
ungated.

:func:`gated_get` re-runs ``utils.scope_gate.check_scan`` on EVERY hop —
initial URL included — and raises :class:`ScopeGateError` the moment any
hop fails.  Callers that batch many URLs catch the error per-item (a
blocked probe is reported, never fired); single-URL tools let it
propagate as a hard failure.  Fail-closed in both shapes: no hop is ever
taken before its verdict.

All framework HTTP tools route through this helper (cors_probe, web_probe,
js_recon); archived_urls locks its endpoint by NOT following redirects at
all.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

from utils.scope_gate import ScopeGateError, check_scan

_REDIRECT_CODES = {301, 302, 303, 307, 308}


def gated_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = True,
    timeout: Tuple[float, float] = (5.0, 10.0),
    max_hops: int = 5,
) -> Tuple[requests.Response, List[Dict[str, Any]]]:
    """GET ``url`` manually following redirects, gate-checking every hop.

    Returns ``(response, hops)`` — ``hops`` is the ordered list of
    ``{"url", "status"}`` visited (first entry is the original URL).  The
    returned Response is the FINAL one.

    Raises:
        ScopeGateError: if the starting URL or ANY redirect target fails
            the armed scope gate, or if the chain exceeds ``max_hops``
            (stopped while still in scope — never fired past the cap).
    """
    hops: List[Dict[str, Any]] = []
    current = (url or "").strip()
    if not current:
        raise ScopeGateError("scope gate: empty URL")
    session = requests.Session()
    try:
        for _ in range(max_hops + 1):
            ok, reason = check_scan(current)
            if not ok:
                where = "initial URL" if not hops else f"redirect hop {len(hops)}"
                raise ScopeGateError(f"scope gate: {reason} ({where})")
            resp = session.get(
                current,
                headers=headers,
                verify=verify,
                timeout=timeout,
                allow_redirects=False,
            )
            hops.append({"url": current, "status": resp.status_code})
            if resp.status_code not in _REDIRECT_CODES:
                return resp, hops
            location = resp.headers.get("Location")
            if not location:
                return resp, hops
            nxt = urljoin(current, location)
            if nxt == current:  # self-redirect guard
                return resp, hops
            current = nxt
        # Hops exhausted while still in scope — stop, never fire past the cap.
        raise ScopeGateError(
            f"scope gate: redirect chain exceeded {max_hops} hops; "
            "stopped (all hops so far were in-scope)"
        )
    finally:
        session.close()


__all__ = ["gated_get"]