"""Tests for the stateful web-session lane (auxiliaries/web_session.py).

Hermetic end-to-end: a stdlib ThreadingHTTPServer plays a CSRF-protected
Django-style app — GET /login/ sets a ``csrftoken`` cookie and renders a
``csrfmiddlewaretoken`` hidden field; POST /login/ demands BOTH the cookie
and the form token plus credentials, then sets ``sessionid`` and 303s to
/dashboard/ which only renders for the authenticated cookie.  The flow the
operator's 192.168.56.106 Django target requires — reproduced locally.

- the scope gate seam (utils.gated_http.check_scan) is stubbed in-process:
  allowed for the happy path, armed-blocking to prove ScopeGateError fires
  BEFORE any connection
- the jar is isolated to a temp COOKIE_JAR_DB per test
- cross-tool continuity: state written by session_get is read by
  session_post and session_request without any caller-side glue
"""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

import utils.cookie_jar as cj
import utils.gated_http as gh
import auxiliaries.web_session as ws
from utils.scope_gate import ScopeGateError

CSRF_COOKIE = "csrftoken=abc123"
CSRF_FORM = "TOK99"


class _MiniDjango(BaseHTTPRequestHandler):
    """Django-style CSRF + session behaviour, stdlib only."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    # helpers ---------------------------------------------------------------

    def _respond(self, code, body: bytes, ctype="text/html", cookies=(), extra=()):
        self.send_response(code)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cookie(self):
        return self.headers.get("Cookie") or ""

    # routes ----------------------------------------------------------------

    def do_GET(self):
        if self.path == "/login/":
            body = (
                "<html><head><title>Login</title></head><body>"
                '<form action="/login/" method="post">'
                f'<input type="hidden" name="csrfmiddlewaretoken" value="{CSRF_FORM}">'
                '<input name="username"><input type="password" name="password">'
                "</form></body></html>"
            ).encode()
            self._respond(200, body, cookies=[CSRF_COOKIE + "; Path=/"])
        elif self.path == "/dashboard/":
            if "sessionid=S1" in self._cookie():
                self._respond(200, b"<html><title>Admin Dashboard</title>Welcome admin</html>")
            else:
                self._respond(
                    302, b"", ctype="text/plain",
                    extra=[("Location", "/login/")],
                )
        else:
            self._respond(404, b"nope", ctype="text/plain")

    def do_POST(self):
        if self.path != "/login/":
            self._respond(404, b"nope", ctype="text/plain")
            return
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode())
        cookie_ok = CSRF_COOKIE in self._cookie()
        csrf_ok = cookie_ok and form.get("csrfmiddlewaretoken") == [CSRF_FORM]
        creds_ok = form.get("username") == ["admin"] and form.get("password") == ["secret"]
        if csrf_ok and creds_ok:
            self._respond(
                303, b"", ctype="text/plain",
                cookies=["sessionid=S1; Path=/"],
                extra=[("Location", "/dashboard/")],
            )
        else:
            msg = f"csrf_ok={csrf_ok} creds_ok={creds_ok}".encode()
            self._respond(403, msg, ctype="text/plain")

    def do_PUT(self):
        custom = self.headers.get("X-Custom") or ""
        body = f'{{"ok": true, "custom": "{custom}"}}'.encode()
        self._respond(200, body, ctype="application/json")


# --- fixtures -----------------------------------------------------------------


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MiniDjango)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture(autouse=True)
def jar_and_gate(tmp_path, monkeypatch):
    # 1) isolate the durable jar to a temp file and reset the singleton
    monkeypatch.setenv("COOKIE_JAR_DB", str(tmp_path / "jar.db"))
    cj._JAR = None
    # 2) stub the scope-gate seam the session lane routes through
    real_check = gh.check_scan
    monkeypatch.setattr(gh, "check_scan", lambda t: (True, "test-stub"))
    yield
    monkeypatch.setattr(gh, "check_scan", real_check)
    jar = cj.get_jar()
    try:
        jar.clear()
        jar.close()
    finally:
        cj._JAR = None


@pytest.fixture()
def base(server):
    return f"http://127.0.0.1:{server.server_port}"


# --- the full CSRF dance ---------------------------------------------------


def test_csrf_login_flow_end_to_end(base):
    # step 1: anonymous GET picks up the csrf cookie + form token
    r1 = ws.session_get(f"{base}/login/")
    assert r1["http_status"] == 200
    assert r1["title"] == "Login"
    assert {c["name"] for c in r1["cookies_received"]} == {"csrftoken"}
    assert r1["tokens_extracted"] == [
        {"name": "csrfmiddlewaretoken", "value": CSRF_FORM, "source": "form"}
    ]

    # step 2: POST with plain creds — CSRF form field + header auto-injected
    r2 = ws.session_post(f"{base}/login/", data={"username": "admin", "password": "secret"})
    assert r2["http_status"] == 200  # after the 303 hop
    assert r2["final_url"].endswith("/dashboard/")
    assert r2["csrf_injected"]["form_field"] == "csrfmiddlewaretoken"
    assert r2["csrf_injected"]["header"] is True
    assert {c["name"] for c in r2["cookies_received"]} == {"sessionid"}
    assert [h["status"] for h in r2["hops"]] == [303, 200]

    # step 3: a fresh call is authenticated purely via jar state
    r3 = ws.session_get(f"{base}/dashboard/")
    assert r3["http_status"] == 200
    assert r3["title"] == "Admin Dashboard"
    assert "sessionid" in r3["cookies_applied"]

    # step 4: the jar holds the whole picture for the operator
    state = cj.get_jar().list_state("127.0.0.1")
    names = {c["name"] for c in state["cookies"]}
    assert {"csrftoken", "sessionid"} <= names


def test_post_without_prior_get_lacks_csrf(base):
    # no session_get first: vault has no token -> server rejects with 403.
    # (header injection alone still fires, cookie jar is empty)
    r = ws.session_post(f"{base}/login/", data={"username": "admin", "password": "secret"})
    assert r["http_status"] == 403
    assert "csrf_ok=False" in r["body_head"]


def test_wrong_credentials_rejected(base):
    ws.session_get(f"{base}/login/")
    r = ws.session_post(f"{base}/login/", data={"username": "admin", "password": "WRONG"})
    assert r["http_status"] == 403
    assert "creds_ok=False" in r["body_head"]
    assert "csrf_ok=True" in r["body_head"]  # the CSRF round-trip still worked


def test_unauthenticated_dashboard_redirects_to_login(base):
    r = ws.session_get(f"{base}/dashboard/")
    assert r["http_status"] == 200  # followed the 302
    assert r["final_url"].endswith("/login/")
    assert r["title"] == "Login"


# --- scope gate enforcement -------------------------------------------------


def test_scope_gate_blocks_before_any_connection(base, monkeypatch):
    monkeypatch.setattr(gh, "check_scan", lambda t: (False, "out of scope"))
    with pytest.raises(ScopeGateError):
        ws.session_get(f"{base}/login/")
    with pytest.raises(ScopeGateError):
        ws.session_post(f"{base}/login/", data={"username": "a", "password": "b"})
    with pytest.raises(ScopeGateError):
        ws.session_request("PUT", f"{base}/x")
    # and nothing was written to the jar by the blocked attempts
    assert cj.get_jar().list_state("127.0.0.1")["cookies"] == []


# --- session_request (arbitrary method) --------------------------------------


def test_session_request_put(base):
    r = ws.session_request("PUT", f"{base}/thing", json_data={"x": 1})
    assert r["http_status"] == 200
    assert '"ok": true' in r["body_head"]


def test_session_request_header_passthrough(base):
    r = ws.session_request("PUT", f"{base}/thing", json_data={"x": 1}, headers={"X-Custom": "yes"})
    assert r["http_status"] == 200
    assert '"custom": "yes"' in r["body_head"]  # server echoes the header back


def test_no_redirect_follow(base):
    ws.session_get(f"{base}/login/")
    r = ws.session_post(
        f"{base}/login/",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert r["http_status"] == 303
    assert [h["status"] for h in r["hops"]] == [303]  # initial response only
    # ... but the sessionid cookie is still captured from the 303 response
    assert {c["name"] for c in r["cookies_received"]} == {"sessionid"}