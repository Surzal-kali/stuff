"""Tests for the universal cookie jar / token vault (utils/cookie_jar.py).

Fully hermetic: every test builds a CookieJarStore against a tmp_path
SQLite file — no network, no live scope state, nothing shared with the
operator's real jar.  Covers:

- domain matching rules (exact, dot-form, subdomain; IP-host guard)
- path matching rules
- store_cookie upsert semantics + cookies_for selection
- server-expiry purge + TTL purge
- cookie-string import ("a=1; b=2") + cookie_header export
- token vault upsert, tokens_for, csrf_for (cookie-derived header)
- extract_csrf_tokens across framework families
  (Django form, Rails meta, Laravel/ASP.NET headers, HTML entities)
- cross-instance durability: two store objects on one file share rows
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

import utils.cookie_jar as cj
from utils.cookie_jar import CookieJarStore, extract_csrf_tokens


@pytest.fixture
def jar(tmp_path):
    store = CookieJarStore(tmp_path / "jar.db")
    yield store
    store.close()


# --- domain / path matching ------------------------------------------------


def test_domain_matches_exact_and_subdomain():
    # host-only cookie (no Domain=): exact host only, never subdomains
    assert cj.domain_matches("example.com", "example.com")
    assert not cj.domain_matches("example.com", "www.example.com")
    # dot-form cookie (Domain= specified): host + all subdomains
    assert cj.domain_matches(".example.com", "example.com")
    assert cj.domain_matches(".example.com", "www.example.com")
    assert cj.domain_matches(".example.com", "deep.www.example.com")
    # but never another registered domain sharing the suffix
    assert not cj.domain_matches(".example.com", "notexample.com")
    assert not cj.domain_matches(".example.com", "example.org")
    assert not cj.domain_matches("example.com", "com")


def test_ip_host_never_matches_dot_form():
    # the guard that keeps a jarred ".56.106" dot-cookie off a raw IP host
    assert cj.domain_matches("192.168.56.106", "192.168.56.106")
    assert not cj.domain_matches("192.168.56.106", "10.192.168.56.106")
    assert not cj.domain_matches("56.106", "192.168.56.106")
    assert not cj.domain_matches("example.com", "192.168.56.106")


def test_path_matches():
    assert cj.path_matches("/", "/anything/at/all")
    assert cj.path_matches("/app", "/app")
    assert cj.path_matches("/app", "/app/login/")
    assert not cj.path_matches("/app", "/")
    assert not cj.path_matches("/app", "/application")
    assert not cj.path_matches("/app", "/other")


# --- cookie storage ----------------------------------------------------------


def test_store_and_select(jar):
    jar.store_cookie("example.com", "sessionid", "abc", origin="test")
    jar.store_cookie("example.com", "theme", "dark", path="/app", origin="test")
    jar.store_cookie("other.com", "sessionid", "xyz", origin="test")

    # cookies_for: domain-matched http.cookiejar.Cookie objects
    got = jar.cookies_for("http://example.com/app/page")
    by_name = {c.name: c.value for c in got}
    assert by_name == {"sessionid": "abc", "theme": "dark"}

    # dot-form cookie (Domain= style) matches a subdomain too
    jar.store_cookie(".example.com", "shared", "S", origin="test")
    got_sub = {c.name: c.value for c in jar.cookies_for("www.example.com/")}
    assert got_sub == {"shared": "S"}

    # host-only cookies stay pinned to their exact host
    assert jar.cookies_for("www.other.com/") == []


def test_store_cookie_upsert(jar):
    jar.store_cookie("example.com", "sessionid", "v1", origin="t")
    jar.store_cookie("example.com", "sessionid", "v2", origin="t")
    got = jar.cookies_for("example.com")
    assert len(got) == 1 and got[0].value == "v2"


def test_requires_domain_and_name(jar):
    assert jar.store_cookie("", "x", "1")["stored"] is False
    assert jar.store_cookie("example.com", "", "1")["stored"] is False


def test_expired_cookie_is_purged(jar):
    jar.store_cookie("example.com", "flash", "gone", expires=time.time() - 10, origin="t")
    jar.store_cookie("example.com", "solid", "keep", origin="t")
    assert [c.name for c in jar.cookies_for("example.com")] == ["solid"]


def test_ttl_purge(tmp_path):
    short = CookieJarStore(tmp_path / "short.db", ttl_hours=1 / 3600)  # 1s TTL
    try:
        short.store_cookie("example.com", "a", "1", origin="t")
        time.sleep(1.05)  # "a" is now past the TTL
        short.store_cookie("example.com", "b", "2", origin="t")  # fresh
        names = {c.name for c in short.cookies_for("example.com")}
        assert names == {"b"}
        # tokens age out on the same clock
        short.store_token("example.com", "tok", "v", origin="t")
        time.sleep(1.05)
        short.store_token("example.com", "tok2", "v2", origin="t")
        toks = {t["name"] for t in short.tokens_for("example.com")}
        assert toks == {"tok2"}
    finally:
        short.close()


# --- import / export ---------------------------------------------------------


def test_import_cookie_string_multipair(jar):
    out = jar.import_cookie_string("example.com", "a=1; b=2; c=three", origin="test")
    assert out["stored"] == ["a", "b", "c"]
    by_name = {c.name: c.value for c in jar.cookies_for("example.com")}
    assert by_name == {"a": "1", "b": "2", "c": "three"}


def test_cookie_header_format(jar):
    jar.store_cookie("example.com", "sessionid", "S", path="/", origin="t")
    jar.store_cookie("example.com", "csrftoken", "C", path="/", origin="t")
    jar.store_cookie("example.com", "other", "O", path="/nope", origin="t")
    header = jar.cookie_header("http://example.com/")
    assert header == "sessionid=S; csrftoken=C"


def test_clear(jar):
    jar.store_cookie("example.com", "a", "1", origin="t")
    jar.store_cookie("other.com", "b", "2", origin="t")
    jar.store_token("example.com", "tok", "v", origin="t")
    jar.clear(domain="example.com")
    assert jar.cookies_for("example.com") == []
    assert jar.tokens_for("example.com") == []
    assert len(jar.cookies_for("other.com")) == 1  # other domains untouched


# --- token vault ---------------------------------------------------------------


def test_token_upsert_and_csrf_for(jar):
    jar.store_token("http://example.com/login/", "csrfmiddlewaretoken", "T1", origin="t")
    assert jar.get_token("example.com", "csrfmiddlewaretoken") == "T1"
    jar.store_token("example.com", "csrfmiddlewaretoken", "T2", origin="t2")
    assert jar.get_token("example.com", "csrfmiddlewaretoken") == "T2"
    assert len(jar.tokens_for("example.com")) == 1  # upsert, not append

    # header derivation prefers a cookie-named csrftoken
    jar.store_cookie("example.com", "csrftoken", "CK", origin="t")
    csrf = jar.csrf_for("example.com")
    assert csrf["form_value"] == "T2"
    assert csrf["header_value"] == "CK"


def test_csrf_for_missing(jar):
    assert jar.csrf_for("example.com")["form_value"] is None


# --- CSRF extraction -----------------------------------------------------------


def test_extract_django_hidden_input_html_escaped():
    html = (
        '<form method="post"><input type="hidden" '
        'name="csrfmiddlewaretoken" value="a1&amp;b2">'
        "</form>"
    )
    toks = extract_csrf_tokens(html)
    assert toks[0] == {"name": "csrfmiddlewaretoken", "value": "a1&b2", "source": "form"}


def test_extract_rails_meta():
    html = '<head><meta name="csrf-token" content="RAILS123"></head>'
    toks = extract_csrf_tokens(html)
    assert toks and toks[0]["value"] == "RAILS123" and toks[0]["source"] == "meta"


def test_extract_aspnet_form_field():
    html = (
        '<form><input name="__RequestVerificationToken" type="hidden" '
        'value="ASPXYZ"/></form>'
    )
    toks = extract_csrf_tokens(html)
    assert toks and toks[0]["name"] == "__RequestVerificationToken"


def test_extract_headers_laravel():
    toks = extract_csrf_tokens("", {"X-XSRF-TOKEN": "EYJ9xyz", "Other": "n"})
    assert toks and toks[0]["value"] == "EYJ9xyz"
    assert toks[0]["source"].startswith("header:")


def test_extract_ignores_non_csrf_hidden_inputs():
    html = '<input type="hidden" name="user_id" value="7">'
    assert extract_csrf_tokens(html) == []


def test_extract_prefers_canonical_form_field():
    html = (
        '<meta name="csrf-token" content="METAV">'
        '<input type="hidden" name="authenticity_token" value="FORMV">'
        '<input type="hidden" name="csrfmiddlewaretoken" value="DJV">'
    )
    toks = extract_csrf_tokens(html)
    assert toks[0]["name"] == "csrfmiddlewaretoken"  # Django outranks meta/others


# --- cross-instance durability (the whole point: state on disk) -------------


def test_two_stores_share_one_file(tmp_path):
    a = CookieJarStore(tmp_path / "shared.db")
    try:
        a.store_cookie("example.com", "sessionid", "shared", origin="a")
    finally:
        a.close()

    b = CookieJarStore(tmp_path / "shared.db")
    try:
        got = {c.name: c.value for c in b.cookies_for("example.com")}
        assert got == {"sessionid": "shared"}
    finally:
        b.close()