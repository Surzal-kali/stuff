"""Tests for auxiliaries/zap.py — scan-config enforcement + helpers.

Mirrors the ffuf scan-config tests (tests_ffuf_hydra.py) for the ZAP
equivalent path.  Covers:

- Finding 1: rate-only configs are applied (not silently dropped when
  no headers are mandated).
- Finding 2: per-rule status is surfaced in the envelope — API failures
  are reported, not swallowed.
- Finding 3: stale framework rules from a previous scope are cleared
  before new ones are applied (cross-program header leak prevention).
- Helpers: _canonical, _status_from_headers, _ensure_https_scheme.
"""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

# Import program_scope BEFORE any test runs so its module-level
# load_dotenv(override=True) fires here, not inside a lazy import during a
# test (which would clobber a monkeypatched WORKSPACE_ROOT).
import auxiliaries.program_scope  # noqa: F401

from auxiliaries.zap import ZAPClient, ZAPAPIError, _canonical, _status_from_headers


# --- helper fixtures --------------------------------------------------------

@pytest.fixture
def zap_client():
    """A ZAPClient with a mocked _get so no daemon is needed."""
    client = ZAPClient.__new__(ZAPClient)
    client.base = "http://127.0.0.1:8090"
    client.api_key = "test-key"
    import requests
    client.session = requests.Session()
    # Action endpoints route through a separate no-retry session; provide
    # one so _get doesn't AttributeError on /action/ views.
    client._action_session = requests.Session()
    return client


def _make_intigriti_cache(tmp_path: Path, handle: str = "test",
                          ua: str | None = None,
                          header: str | None = None,
                          rate: int | None = None) -> Path:
    """Write an intigriti manifest cache file and return its path."""
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    tr = {}
    if ua is not None:
        tr["user_agent"] = ua
    if header is not None:
        tr["request_header"] = header
    if rate is not None:
        tr["max_requests_per_second"] = rate
    (cache_dir / f"intigriti_{handle}.json").write_text(json.dumps({
        "platform": "intigriti", "handle": handle,
        "testing_requirements": tr,
    }))
    return cache_dir / f"intigriti_{handle}.json"


def _make_h1_cache(tmp_path: Path, handle: str = "crypto",
                   policy: str = "") -> Path:
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{handle}.json").write_text(json.dumps({
        "handle": handle, "platform": "h1",
        "policy": policy, "in_scope": [], "out_of_scope_assets": [],
    }))
    return cache_dir / f"{handle}.json"


# --- _canonical / _status_from_headers / _ensure_https_scheme ----------------

def test_canonical_preserves_query_string():
    assert _canonical("http://host/page?a=1") == "host/page?a=1"
    assert _canonical("http://HOST/page/") == "host/page"
    assert _canonical("https://h:443/p?q=2&r=3") == "h/p?q=2&r=3"


def test_status_from_headers():
    assert _status_from_headers("HTTP/1.1 200 OK\r\nContent-Type: t\r\n") == "200"
    assert _status_from_headers("HTTP/1.1 404 Not Found\r\n") == "404"
    assert _status_from_headers("") == ""
    assert _status_from_headers("garbage") == ""


def test_ensure_https_scheme_prepends_https():
    raw = "GET /path HTTP/1.1\nHost: example.com\n\n"
    out = ZAPClient._ensure_https_scheme(raw)
    assert "https://example.com/path" in out


def test_ensure_https_scheme_passes_absolute_form():
    raw = "GET http://host/path HTTP/1.1\nHost: host\n\n"
    out = ZAPClient._ensure_https_scheme(raw)
    assert out == raw  # already absolute — untouched


def test_ensure_https_scheme_no_host_passthrough():
    raw = "GET /path HTTP/1.1\n\n"
    out = ZAPClient._ensure_https_scheme(raw)
    assert out == raw


# --- Finding 1: rate-only configs are applied (not silently dropped) --------

def test_configure_rate_only_config_applies_rate(zap_client, monkeypatch, tmp_path):
    """A program mandating ONLY a rate cap (no custom UA/header) must still
    get its rate limit rule applied — not silently skipped."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    _make_intigriti_cache(tmp_path, rate=15)

    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://target.example.com", "test", "intigriti")

    assert cfg is not None
    assert cfg["max_requests_per_second"] == 15
    assert cfg["headers"] == {}  # no headers mandated

    # Rate limit rule must have been added
    add_calls = [c for c in calls if c[0] == "network/action/addRateLimitRule"]
    assert len(add_calls) == 1
    assert add_calls[0][1]["requestsPerSecond"] == "15"
    assert add_calls[0][1]["matchString"] == "target.example.com"

    # rule_status must show the rate rule as applied
    statuses = [s for s in cfg["rule_status"] if s["type"] == "ratelimit"]
    assert any(s["status"] == "applied" for s in statuses)


def test_configure_rate_only_no_headers_no_replacer_rules(zap_client, monkeypatch, tmp_path):
    """Rate-only config must NOT add any replacer rules (no headers)."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    _make_intigriti_cache(tmp_path, rate=10)

    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://target.com", "test", "intigriti")

    add_rule_calls = [c for c in calls if c[0] == "replacer/action/addRule"]
    assert len(add_rule_calls) == 0  # no headers → no replacer rules


def test_configure_full_config_applies_headers_and_rate(zap_client, monkeypatch, tmp_path):
    """Full config (UA + header + rate) applies all three."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "researcher1")
    _make_intigriti_cache(
        tmp_path,
        ua="researcher-ua",
        header="X-Intigriti-Username: {Username}",
        rate=20,
    )

    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://adobe.example.com", "test", "intigriti")

    assert cfg is not None
    assert cfg["headers"]["User-Agent"] == "researcher-ua"
    assert cfg["headers"]["X-Intigriti-Username"] == "researcher1"
    assert cfg["max_requests_per_second"] == 20

    add_rule_calls = [c for c in calls if c[0] == "replacer/action/addRule"]
    assert len(add_rule_calls) == 2  # UA + custom header
    rate_calls = [c for c in calls if c[0] == "network/action/addRateLimitRule"]
    assert len(rate_calls) == 1


def test_configure_none_when_no_requirements(zap_client, monkeypatch, tmp_path):
    """When the program mandates nothing (no UA, no header, no rate),
    configure_scan_config returns None."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    _make_intigriti_cache(tmp_path)  # empty testing_requirements

    monkeypatch.setattr(zap_client, "_get", lambda *a, **kw: {})
    cfg = zap_client.configure_scan_config(
        "http://target.com", "test", "intigriti")
    assert cfg is None


# --- Finding 2: per-rule status surfaces API failures -----------------------

def test_configure_surfaces_replacer_failure(zap_client, monkeypatch, tmp_path):
    """When a replacer addRule call fails, the failure is surfaced in
    rule_status — not silently swallowed."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "researcher1")
    _make_intigriti_cache(
        tmp_path,
        ua="researcher-ua",
        header="X-Intigriti-Username: {Username}",
        rate=10,
    )

    def fake_get(view, **q):
        if view == "replacer/action/addRule":
            raise RuntimeError("ZAP daemon error")
        if view == "replacer/view/rules":
            return {"rules": []}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": []}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://target.com", "test", "intigriti")

    assert cfg is not None
    failed = [s for s in cfg["rule_status"] if "failed" in s.get("status", "")]
    assert len(failed) >= 2  # both replacer rules failed
    assert all("ZAP daemon error" in s["status"] for s in failed)


def test_configure_surfaces_ratelimit_failure(zap_client, monkeypatch, tmp_path):
    """When the rate-limit addRateLimitRule call fails, the failure is
    surfaced in rule_status."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    _make_intigriti_cache(tmp_path, rate=10)

    def fake_get(view, **q):
        if view == "network/action/addRateLimitRule":
            raise RuntimeError("network component unavailable")
        if view == "replacer/view/rules":
            return {"rules": []}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": []}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://target.com", "test", "intigriti")

    assert cfg is not None
    rl_statuses = [s for s in cfg["rule_status"] if s["type"] == "ratelimit"]
    assert any("failed" in s["status"] for s in rl_statuses)
    assert any("network component unavailable" in s["status"] for s in rl_statuses)


# --- Finding 3: stale rules cleared before applying new ones ---------------

def test_clear_ri_rules_removes_stale_replacer(zap_client, monkeypatch):
    """clear_ri_rules enumerates existing rules and removes those with
    our _RI_PREFIX."""
    from auxiliaries.zap import _RI_PREFIX

    existing_rules = [
        {"description": f"{_RI_PREFIX}header-user-agent", "matchString": "User-Agent"},
        {"description": f"{_RI_PREFIX}header-x-intigriti-username", "matchString": "X-Intigriti-Username"},
        {"description": "user-defined-rule", "matchString": "X-Custom"},
    ]

    def fake_get(view, **q):
        if view == "replacer/view/rules":
            return {"rules": existing_rules}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": []}
        # removeRule calls
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cleared = zap_client.clear_ri_rules()
    removed = [c for c in cleared if c["status"] == "removed"]
    assert len(removed) == 2  # only our 2 prefixed rules
    # user-defined rule must NOT be touched
    assert all("user-defined" not in c["description"] for c in cleared)


def test_clear_ri_rules_removes_stale_ratelimit(zap_client, monkeypatch):
    """clear_ri_rules also clears stale rate-limit rules."""
    from auxiliaries.zap import _RI_PREFIX

    def fake_get(view, **q):
        if view == "replacer/view/rules":
            return {"rules": []}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": [
                {"description": f"{_RI_PREFIX}ratelimit-old.host.com"},
                {"description": "user-ratelimit-rule"},
            ]}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cleared = zap_client.clear_ri_rules()
    removed = [c for c in cleared if c["status"] == "removed" and c["type"] == "ratelimit"]
    assert len(removed) == 1
    assert removed[0]["description"] == f"{_RI_PREFIX}ratelimit-old.host.com"


def test_configure_clears_stale_before_applying(zap_client, monkeypatch, tmp_path):
    """configure_scan_config calls clear_ri_rules before applying new rules,
    so stale rules from a previous program don't leak."""
    from auxiliaries.zap import _RI_PREFIX

    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "researcher1")
    _make_intigriti_cache(
        tmp_path,
        ua="new-ua",
        header="X-Intigriti-Username: {Username}",
        rate=15,
    )

    call_log = []
    def fake_get(view, **q):
        call_log.append(view)
        if view == "replacer/view/rules":
            return {"rules": [
                {"description": f"{_RI_PREFIX}header-x-old-program-header"},
            ]}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": [
                {"description": f"{_RI_PREFIX}ratelimit-old.host.com"},
            ]}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://new.target.com", "test", "intigriti")

    assert cfg is not None
    # Verify listing happened before adding
    list_idx = call_log.index("replacer/view/rules")
    add_indices = [i for i, v in enumerate(call_log) if v == "replacer/action/addRule"]
    assert all(i > list_idx for i in add_indices)

    # Stale rules were removed
    removed = [s for s in cfg["rule_status"] if s["status"] == "removed"]
    assert any("old-program-header" in s["description"] for s in removed)
    assert any("ratelimit-old.host.com" in s["description"] for s in removed)

    # New rules were applied
    applied = [s for s in cfg["rule_status"] if s["status"] == "applied"]
    assert any("header-user-agent" in s["description"] for s in applied)


# --- H1 default identification header (parity with ffuf tests) --------------

def test_configure_h1_default_header(zap_client, monkeypatch, tmp_path):
    """H1 programs get the X-HackerOne-Research identification header
    auto-applied to the ZAP daemon."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("H1_API_USERNAME", "researcher1")
    _make_h1_cache(tmp_path)

    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        if view == "replacer/view/rules":
            return {"rules": []}
        if view == "network/view/getRateLimitRules":
            return {"getRateLimitRules": []}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    cfg = zap_client.configure_scan_config(
        "http://target.com", "crypto", "h1")

    assert cfg is not None
    assert cfg["headers"]["X-HackerOne-Research"] == "researcher1"
    add_calls = [c for c in calls if c[0] == "replacer/action/addRule"]
    assert any("X-HackerOne-Research" in c[1].get("matchString", "") for c in add_calls)


# --- no scope → no config (parity with ffuf) --------------------------------

def test_configure_no_scope_returns_none(zap_client, monkeypatch):
    """No scope_handle → no config applied."""
    monkeypatch.setattr(zap_client, "_get", lambda *a, **kw: {})
    # configure_scan_config is only called when scope_handle is provided,
    # but if called with falsy handle, get_scan_config loads no manifest.
    monkeypatch.setenv("WORKSPACE_ROOT", "/nonexistent")
    cfg = zap_client.configure_scan_config(
        "http://target.com", "nonexistent_program", "intigriti")
    assert cfg is None


# --- Regression: AJAX spider returns no scan ID (singleton) -----------------

def test_ajax_spider_returns_result_not_empty(zap_client, monkeypatch):
    """ajaxSpider/action/scan returns {"Result": "OK"} — no "scan" key.
    The method must return a non-empty, meaningful value, NOT ""."""
    monkeypatch.setattr(zap_client, "_get",
                        lambda v, **q: {"Result": "OK"})
    result = zap_client.ajax_spider("http://example.com")
    assert result != ""
    assert result == "OK"


# --- Regression: ZAPAPIError surfaces error code + message ------------------

def test_zap_api_error_carries_code_and_message():
    err = ZAPAPIError(400, "url_not_found", "URL Not Found in the Scan Tree")
    assert err.status_code == 400
    assert err.code == "url_not_found"
    assert "URL Not Found in the Scan Tree" in str(err)


def test_get_raises_zap_api_error_on_400(zap_client, monkeypatch):
    """When ZAP returns 400 with an error body, _get raises ZAPAPIError
    with the code and message — not a bare HTTPError."""
    import requests as _requests
    from unittest import mock

    fake_resp = mock.Mock()
    fake_resp.ok = False
    fake_resp.status_code = 400
    fake_resp.text = '{"code":"url_not_found","message":"URL Not Found in the Scan Tree"}'
    fake_resp.json.return_value = {"code": "url_not_found",
                                   "message": "URL Not Found in the Scan Tree"}
    # "ascan/action/scan" is an action endpoint — _get routes it through
    # _action_session, not session.
    monkeypatch.setattr(zap_client._action_session, "get",
                        lambda *a, **kw: fake_resp)
    with pytest.raises(ZAPAPIError) as exc_info:
        zap_client._get("ascan/action/scan", url="http://nope.invalid")
    assert exc_info.value.code == "url_not_found"
    assert "URL Not Found" in exc_info.value.message


# --- Regression: spider max_depth uses setOptionMaxDepth --------------------

def test_spider_sets_max_depth_via_option(zap_client, monkeypatch):
    """spider() must call setOptionMaxDepth when max_depth != 5, because
    spider/action/scan doesn't accept a maxDepth parameter."""
    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        if view == "spider/action/scan":
            return {"scan": "0"}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    zap_client.spider("http://example.com", max_depth=10)

    set_depth_calls = [c for c in calls if c[0] == "spider/action/setOptionMaxDepth"]
    assert len(set_depth_calls) == 1
    assert set_depth_calls[0][1]["Integer"] == "10"


def test_spider_skips_set_option_when_default_depth(zap_client, monkeypatch):
    """spider() should NOT call setOptionMaxDepth when max_depth == 5
    (the ZAP default) — avoids an unnecessary API round-trip."""
    calls = []
    def fake_get(view, **q):
        calls.append((view, q))
        if view == "spider/action/scan":
            return {"scan": "0"}
        return {}
    monkeypatch.setattr(zap_client, "_get", fake_get)

    zap_client.spider("http://example.com", max_depth=5)

    set_depth_calls = [c for c in calls if c[0] == "spider/action/setOptionMaxDepth"]
    assert len(set_depth_calls) == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
