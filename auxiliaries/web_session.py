"""Stateful HTTP lane — the tools that CARRY the universal cookie jar.

The framework's one-shot web tools (web_probe, cors_probe, ssrf_probe)
answer "what does this surface look like".  They can't WALK it: every
call starts cookieless, so CSRF-guarded middleware (Django's
``csrfmiddlewaretoken`` + ``csrftoken`` cookie being the canonical case on
192.168.56.106) rejects everything at the front door.  This module is
the stateful counterpart, built on the universal jar + token vault
(``utils/cookie_jar.py`` — SQLite, shared across every lane/process):

- ``session_get``  — GET with jar state applied, Set-Cookie persisted,
  CSRF tokens auto-extracted (form hidden fields, meta tags, response
  headers) into the vault.
- ``session_post`` — POST with the SAME state plus auto-CSRF injection:
  the stored form token (``csrfmiddlewaretoken`` / ``authenticity_token``
  / ``_token`` ...) goes into the body, an ``X-CSRFToken`` header goes out
  (cookie-derived for Django, meta-derived otherwise).
- ``session_request`` — arbitrary-method jar-aware request for the odd
  shapes (PUT/DELETE/HEAD, JSON APIs) — cookies applied + persisted, no
  auto-CSRF.

The canonical Django flow these enable::

    session_get  http://target/login/          -> jar: csrftoken cookie
                                                   vault: csrfmiddlewaretoken
    session_post http://target/login/  data="user=..&pass=.."
                                        -> jar: sessionid, 302 followed
    session_get  http://target/admin/           -> 200, authenticated

Every hop of every request is scope-gate validated via
``utils.gated_http.gated_request`` (per-hop ``check_scan`` — a 302 to an
out-of-scope host raises ``ScopeGateError`` before any traffic fires),
identically to the rest of the framework's HTTP lane.  The jar itself only
stores strings; these tools are the only place it becomes traffic, and the
gate sits in front of every packet.

Blocking by design (sync ``requests`` through the gated hop loop); the
Brain dispatchers run sync tools in worker threads, per the framework's
blocking-calls convention.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

import requests

from constants import framework_tool
from utils.cookie_jar import extract_csrf_tokens, get_jar
from utils.gated_http import gated_request
from utils.scope_gate import ScopeGateError

_UA = "framework-web-session/1.0 (+stateful-audit-lane)"
_TOKEN_SCAN_LIMIT = 262144  # extract tokens from at most this much body


def _merge_headers(
    base: Optional[Dict[str, str]], extra: Optional[Dict[str, str]]
) -> Dict[str, str]:
    merged: Dict[str, str] = {"User-Agent": _UA}
    if base:
        merged.update({str(k): str(v) for k, v in base.items()})
    if extra:
        merged.update({str(k): str(v) for k, v in extra.items()})
    return merged


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _form_encode(data: Any) -> Tuple[str, Dict[str, str]]:
    """Normalise a ``data`` argument to ``(form_string, original_dict)``.

    Dict -> urlencoded string (kept separately for name lookups);
    string -> used verbatim (parsed for name lookups); anything else
    (requests' odd forms) -> (None, {}).
    """
    if data is None:
        return "", {}
    if isinstance(data, dict):
        return urlencode(data, doseq=True), {str(k): str(v) for k, v in data.items()}
    if isinstance(data, str):
        try:
            return data, dict(parse_qsl(data, keep_blank_values=True))
        except Exception:  # noqa: BLE001 - unparseable body: send verbatim
            return data, {}
    return "", {}


def _csrf_inject(
    host: str, data: Any, json_data: Any, headers: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """Best-effort CSRF injection for a POST. Returns what was injected."""
    jar = get_jar()
    csrf = jar.csrf_for(host)
    injected: Dict[str, Any] = {"form_field": None, "header": None}
    if csrf.get("header_value"):
        headers.setdefault("X-CSRFToken", csrf["header_value"])
        headers.setdefault("X-CSRF-TOKEN", csrf["header_value"])
        injected["header"] = csrf["header_value"]
    if csrf.get("form_name") and csrf.get("form_value") and not json_data:
        name, value = csrf["form_name"], csrf["form_value"]
        if isinstance(data, dict):
            if name not in data:
                data = dict(data)
                data[name] = value
                injected["form_field"] = (name, value, "dict")
        elif isinstance(data, str):
            existing = dict(parse_qsl(data, keep_blank_values=True))
            if name not in existing:
                sep = "" if not data else ("&" if not data.endswith("&") else "")
                data = f"{data}{sep}{urlencode({name: value})}"
                injected["form_field"] = (name, value, "str")
        elif data is None:
            data = urlencode({name: value})
            injected["form_field"] = (name, value, "synthesized")
    injected["data"] = data if injected.get("form_field") else None
    return injected if (injected["form_field"] or injected["header"]) else None


def _title_of(text: str) -> Optional[str]:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


def _do_session_request(
    method: str,
    url: str,
    *,
    data: Any = None,
    json_data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    insecure: bool = False,
    timeout: float = 15.0,
    max_hops: int = 5,
    follow_redirects: bool = True,
    body_limit: int = 4096,
    extract_tokens: bool = True,
    csrf: bool = False,
) -> Dict[str, Any]:
    """Shared engine: jar-apply -> gated request -> jar-persist -> envelope."""
    jar = get_jar()
    host = _host_of(url)
    if not host:
        raise ScopeGateError(f"scope gate: cannot parse host from URL {url!r}")

    session = requests.Session()
    applied = jar.apply_to_session(session, url)

    merged = _merge_headers(headers, None)
    injected = None
    if csrf and (method or "").upper() == "POST":
        injected = _csrf_inject(host, data, json_data, merged)
        if injected and injected.get("data") is not None:
            data = injected["data"]  # body gained the CSRF form field

    resp, hops = gated_request(
        method,
        url,
        headers=merged,
        data=data,
        json=json_data,
        verify=not insecure,
        timeout=(5.0, timeout),
        max_hops=max_hops,
        allow_redirects=follow_redirects,
        session=session,
    )

    final_url = hops[-1]["url"] if hops else url
    received = jar.store_response_cookies(session.cookies, origin=final_url)
    session.close()

    text = ""
    ctype = resp.headers.get("Content-Type", "")
    if "text" in ctype or "html" in ctype or "json" in ctype or "xml" in ctype or not ctype:
        try:
            text = resp.text[: _TOKEN_SCAN_LIMIT]
        except Exception:  # noqa: BLE001 - decode issues shouldn't kill the call
            text = ""
    tokens_extracted: List[Dict[str, str]] = []
    if extract_tokens:
        for t in extract_csrf_tokens(text, dict(resp.headers)):
            jar.store_token(
                host, t["name"], t["value"],
                token_type="csrf", origin=final_url, context=t["source"],
            )
            tokens_extracted.append(t)

    domain_state = jar.list_state(host)
    envelope: Dict[str, Any] = {
        "status": "Success",
        "method": (method or "GET").upper(),
        "url": url,
        "final_url": final_url,
        "http_status": resp.status_code,
        "reason": resp.reason,
        "hops": hops,
        "cookies_applied": applied,
        "cookies_received": [c for c in received if c.get("changed")],
        "cookies_now": [c["name"] for c in domain_state["cookies"]],
        "csrf_injected": (
            {
                "form_field": injected["form_field"][0] if injected and injected.get("form_field") else None,
                "header": bool(injected and injected.get("header")),
            }
            if csrf
            else None
        ),
        "tokens_extracted": tokens_extracted,
        "content_type": ctype,
        "title": _title_of(text),
        "body_length": len(resp.content or b""),
        "body_head": text[: max(0, int(body_limit))],
    }
    return envelope


def _session_digest(result: Dict[str, Any]) -> Dict[str, str]:
    """Result-projection digest: state transitions, not page bodies."""
    if result.get("status") != "Success":
        return {"summary": f"failed: {result.get('error', 'unknown')}", "row_hint_format": ""}
    parts = [
        f"{result.get('method')} {result.get('final_url')} -> {result.get('http_status')}"
    ]
    if result.get("cookies_received"):
        names = ", ".join(c["name"] for c in result["cookies_received"])
        parts.append(f"new/updated cookies: {names}")
    if result.get("cookies_applied"):
        parts.append(f"sent: {', '.join(result['cookies_applied'])}")
    if result.get("csrf_injected", {}).get("form_field"):
        parts.append(f"csrf injected: {result['csrf_injected']['form_field']}")
    if result.get("tokens_extracted"):
        parts.append(
            "tokens: " + ", ".join(t["name"] for t in result["tokens_extracted"])
        )
    if result.get("title"):
        parts.append(f"title: {result['title']}")
    summary = " | ".join(parts)
    hint = (
        "full response incl. body_head is in scratch; filter it with "
        "scratch_search, or call jar_state for the stored cookie/token values"
    )
    return {"summary": summary, "row_hint_format": hint}


@framework_tool(
    "Stateful HTTP GET: fetch a URL with the universal cookie jar applied "
    "(session cookies, CSRF cookies) and persist every Set-Cookie back into "
    "it, auto-extracting CSRF tokens (Django csrfmiddlewaretoken, Rails "
    "authenticity_token, meta csrf-token, X-CSRFToken headers) into the "
    "token vault. This is step one of walking any stateful/CSRF-protected "
    "web app (Django admin, login flows) — the state lives in the jar and "
    "every later session_get/session_post carries it. Per-hop scope-gated "
    "like all framework HTTP. Follow with session_post on the login form.",
    next_hints=[
        "session_post on the login form action URL",
        "jar_state to inspect collected cookies/tokens",
        "report_finding",
    ],
    result_digest=_session_digest,
)
def session_get(
    url: str,
    insecure: bool = False,
    timeout: float = 12.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """GET ``url`` carrying jar state; persist cookies; extract CSRF tokens.

    Args:
        url: Absolute URL (``http://192.168.56.106/login/``).  Every
            redirect hop is scope-gate validated.
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body to return as ``body_head`` (full
            body stays bounded by this; token extraction scans deeper
            internally).
        follow_redirects: Follow 3xx hops (default) or return the 3xx.
        headers: Extra request headers (dict).
    """
    return _do_session_request(
        "GET", url,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True,
    )


@framework_tool(
    "Stateful HTTP POST with automatic CSRF handling — the Django (and "
    "Rails/Laravel/ASP.NET) login-flow workhorse. Sends cookies from the "
    "universal jar AND injects the stored CSRF token: the form field "
    "(csrfmiddlewaretoken/authenticity_token/...) into the POST body, plus "
    "an X-CSRFToken header matching the csrftoken cookie. Set-Cookie "
    "responses (sessionid!) persist to the jar, so the flow "
    "session_get login page -> session_post credentials -> session_get "
    "authenticated page just works. Body may be a form string or dict; "
    "json_data for JSON endpoints (CSRF header still injected). Per-hop "
    "scope-gated.",
    next_hints=[
        "session_get the post-login page to confirm authenticated state",
        "jar_state to see the session cookies",
        "report_finding",
    ],
    result_digest=_session_digest,
)
def session_post(
    url: str,
    data: Any = None,
    json_data: Any = None,
    auto_csrf: bool = True,
    insecure: bool = False,
    timeout: float = 15.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """POST ``url`` with jar state + auto-injected CSRF token.

    Args:
        url: Absolute POST target (the form's action URL).
        data: Form body — a dict (``{"username": "admin", "password": "x"}``)
            or an urlencoded string (``"username=admin&password=x"``).  The
            stored CSRF form field is appended automatically unless the
            name is already present.
        json_data: JSON body for API endpoints (``data`` must be None);
            CSRF goes out as a header, not a form field.
        auto_csrf: Inject the stored CSRF token (default true). Turn off
            for endpoints with no CSRF middleware.
        insecure: Skip TLS verification.
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body returned as ``body_head``.
        follow_redirects: Follow the post-login 302 (default) — set False
            to inspect the raw 3xx.
        headers: Extra request headers (dict).
    """
    return _do_session_request(
        "POST", url,
        data=data, json_data=json_data,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True, csrf=auto_csrf,
    )


@framework_tool(
    "Stateful HTTP request with an arbitrary method (PUT/DELETE/PATCH/HEAD/"
    "OPTIONS): cookies from the universal jar are applied and every "
    "Set-Cookie is persisted, but no automatic CSRF injection — for API "
    "endpoints, state-changing verbs, and odd shapes the session_get/"
    "session_post pair doesn't cover. Auth headers go in ``headers`` "
    "(e.g. Authorization: Bearer ... — store the token with jar_store_token "
    "to keep it in the vault). Per-hop scope-gated like all framework HTTP.",
    next_hints=["session_get", "jar_state", "report_finding"],
    result_digest=_session_digest,
)
def session_request(
    method: str,
    url: str,
    data: Any = None,
    json_data: Any = None,
    insecure: bool = False,
    timeout: float = 15.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Jar-aware request with any HTTP method.

    Args:
        method: HTTP verb (``PUT``, ``DELETE``, ``PATCH``, ``HEAD``, ...).
        url: Absolute URL; every redirect hop is scope-gate validated.
        data: Form body (dict or urlencoded string).
        json_data: JSON body (``data`` must be None).
        insecure: Skip TLS verification.
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body returned as ``body_head``.
        follow_redirects: Follow 3xx hops (default true).
        headers: Extra request headers (dict) — e.g. Authorization bearer.
    """
    return _do_session_request(
        method, url,
        data=data, json_data=json_data,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True,
    )


__all__ = ["session_get", "session_post", "session_request"]