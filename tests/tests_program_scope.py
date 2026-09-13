"""Tests for auxiliaries/program_scope.py — scope manifest, matching, gate.

Covers:
- _match_asset across WILDCARD/URL/DOMAIN/CIDR/IP/ANDROID/IOS/BLOCKCHAIN.
- load_program_scope builds a manifest from a mocked H1 API and writes the
  amass-compatible .scope file (DOMAIN/WILDCARD/URL -> host patterns).
- check_scope returns in/out + matched asset details.
- check_reportable gates against excluded categories + weakness allowlist.
- _build_manifest returns auth_required when no H1 credentials are set.
- .scope file format is consumed correctly by amass._load_scope.
"""

import json
import os
from unittest import mock

import pytest

from auxiliaries import program_scope as ps
from auxiliaries.amass import _load_scope, _in_scope


# --- fixtures ----------------------------------------------------------------

MOCK_STRUCTURED_SCOPES = {
    "data": [
        {"id": "1", "type": "structured-scope", "attributes": {
            "asset_type": "WILDCARD", "asset_identifier": "*.crypto.com",
            "eligible_for_bounty": True, "eligible_for_submission": True,
            "max_severity": "critical", "instruction": "All crypto.com subdomains",
            "confidentiality_requirement": "high", "integrity_requirement": "high",
            "availability_requirement": "high", "reference": "C001",
            "updated_at": "2026-09-01T00:00:00Z"}},
        {"id": "2", "type": "structured-scope", "attributes": {
            "asset_type": "URL", "asset_identifier": "https://crypto.com/exchange",
            "eligible_for_bounty": True, "eligible_for_submission": True,
            "max_severity": "high", "instruction": None,
            "confidentiality_requirement": "high", "integrity_requirement": "high",
            "availability_requirement": "low", "reference": "C002",
            "updated_at": "2026-09-01T00:00:00Z"}},
        {"id": "3", "type": "structured-scope", "attributes": {
            "asset_type": "ANDROID", "asset_identifier": "co.mona.android",
            "eligible_for_bounty": True, "eligible_for_submission": True,
            "max_severity": "medium", "instruction": None,
            "confidentiality_requirement": "high", "integrity_requirement": "high",
            "availability_requirement": "none", "reference": "C003",
            "updated_at": "2026-08-17T00:00:00Z"}},
        {"id": "4", "type": "structured-scope", "attributes": {
            "asset_type": "OTHER", "asset_identifier": "com.defi.wallet",
            "eligible_for_bounty": False, "eligible_for_submission": False,
            "max_severity": "none", "instruction": "DeFi wallet — out of scope",
            "confidentiality_requirement": "none", "integrity_requirement": "none",
            "availability_requirement": "none", "reference": "C004",
            "updated_at": "2026-08-17T00:00:00Z"}},
    ],
    "links": {},
}

MOCK_EXCLUSIONS = {
    "data": [
        {"id": "x1", "type": "scope-exclusion", "attributes": {
            "category": "Missing security headers",
            "details": "CSP/HSTS/X-Frame-Options absent without exploitability",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}},
        {"id": "x2", "type": "scope-exclusion", "attributes": {
            "category": "Brute force on rate-limited logins",
            "details": "Credential brute force against properly rate-limited endpoints",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}},
    ],
    "links": {},
}

MOCK_WEAKNESSES = {
    "data": [
        {"id": "w1", "type": "weakness", "attributes": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command",
            "external_id": "cwe-89", "description": "SQL injection",
            "created_at": "2026-01-01T00:00:00Z"}},
        {"id": "w2", "type": "weakness", "attributes": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "external_id": "cwe-352", "description": "CSRF",
            "created_at": "2026-01-01T00:00:00Z"}},
    ],
    "links": {},
}

MOCK_PROGRAM = {
    "data": {"id": "crypto", "type": "program", "attributes": {
        "handle": "crypto", "policy": "We only accept reproducible vulns with PoC."}},
}


def _mock_get(path, params=None, **kw):
    """Route mocked _get calls to the right fixture."""
    if path.endswith("/structured_scopes"):
        return (200, MOCK_STRUCTURED_SCOPES)
    if path.endswith("/scope_exclusions"):
        return (200, MOCK_EXCLUSIONS)
    if path.endswith("/weaknesses"):
        return (200, MOCK_WEAKNESSES)
    if path.endswith("/programs/crypto"):
        return (200, MOCK_PROGRAM)
    if path == "/hackers/hacktivity":
        # Simulate a real feed: mostly undisclosed items with redacted
        # title/substate/url, plus the always-present fields.
        qs = (params or {}).get("queryString", "")
        if "AND " in qs:
            # Filtered query — public endpoint silently ignores the filter
            # and returns 0 (T-005 scenario).
            return (200, {"data": []})
        # Bare team_handle query returns items.
        return (200, {"data": [
            {"id": 3981275, "type": "hacktivity_item", "attributes": {
                "title": None, "substate": None, "severity_rating": None,
                "cwe": None, "url": None, "disclosed_at": None,
                "disclosed": False, "submitted_at": "2026-08-30T21:50:43.500Z",
                "latest_disclosable_action": "Activities::BountyAwarded",
                "latest_disclosable_activity_at": "2026-09-03T08:23:59.873Z",
                "votes": 3, "total_awarded_amount": 100},
                "relationships": {"reporter": {"data": {"type": "user",
                 "attributes": {"name": "p4p3r", "username": "p4p3r_hak"}}}}},
            {"id": 1, "type": "hacktivity_item", "attributes": {
                "title": "SSRF in avatar upload", "substate": "Resolved",
                "severity_rating": "high", "cwe": "SSRF",
                "url": "https://hackerone.com/reports/1", "disclosed_at": "2026-08-01T00:00:00Z",
                "disclosed": True, "submitted_at": "2026-07-15T10:00:00Z",
                "latest_disclosable_action": "Activities::BugResolved",
                "latest_disclosable_activity_at": "2026-08-01T00:00:00Z",
                "votes": 12, "total_awarded_amount": 500},
                "relationships": {"reporter": {"data": {"type": "user",
                 "attributes": {"name": "test", "username": "testuser"}}}}},
        ]})
    return (404, {"errors": [{"status": 404}]})


@pytest.fixture(autouse=True)
def _creds(monkeypatch):
    monkeypatch.setenv("H1_API_USERNAME", "testuser")
    monkeypatch.setenv("H1_API_TOKEN", "testtoken")
    yield


@pytest.fixture
def loaded_manifest(monkeypatch, tmp_path):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    with mock.patch.object(ps, "_get", side_effect=_mock_get):
        m = ps.load_program_scope("crypto", refresh=True)
    return m, tmp_path


# --- matching ---------------------------------------------------------------

@pytest.mark.parametrize("target,asset_idx,expected", [
    ("api.crypto.com", 0, True),
    ("crypto.com", 0, True),
    ("sub.api.crypto.com", 0, True),
    ("evil.com", 0, False),
    ("https://crypto.com/exchange/BTC", 1, True),
    ("https://crypto.com/exchange", 1, True),
    ("https://crypto.com/nft", 1, False),
    ("crypto.com", 1, False),                 # root not under /exchange path
    ("co.mona.android", 2, True),
    ("com.other.app", 2, False),
])
def test_match_asset(target, asset_idx, expected):
    asset = MOCK_STRUCTURED_SCOPES["data"][asset_idx]["attributes"]
    assert ps._match_asset(target, asset) is expected


def test_match_cidr():
    assert ps._match_asset("10.0.0.5", {"asset_type": "CIDR", "asset_identifier": "10.0.0.0/24"}) is True
    assert ps._match_asset("10.0.1.5", {"asset_type": "CIDR", "asset_identifier": "10.0.0.0/24"}) is False


def test_match_ip():
    assert ps._match_asset("1.2.3.4", {"asset_type": "IP", "asset_identifier": "1.2.3.4"}) is True
    assert ps._match_asset("1.2.3.5", {"asset_type": "IP", "asset_identifier": "1.2.3.4"}) is False


# --- load_program_scope ------------------------------------------------------

def test_load_manifest_structure(loaded_manifest):
    m, _ = loaded_manifest
    assert m["handle"] == "crypto"
    assert m["status"] == "ok"
    assert m["counts"]["in_scope"] == 3
    assert m["counts"]["out_of_scope_assets"] == 1
    assert m["counts"]["excluded_categories"] == 2
    assert m["counts"]["weaknesses"] == 2
    assert "We only accept reproducible" in m["policy"]
    # out-of-scope asset correctly split out
    oos = [a for a in m["out_of_scope_assets"] if a["asset_identifier"] == "com.defi.wallet"]
    assert len(oos) == 1 and oos[0]["eligible_for_submission"] is False


def test_scope_file_written_amass_compatible(loaded_manifest):
    m, tmp_path = loaded_manifest
    scope_file = tmp_path / ".scope"
    assert scope_file.is_file()
    text = scope_file.read_text()
    # WILDCARD and URL-host assets become patterns; ANDROID does NOT (not a domain)
    assert "*.crypto.com" in text
    assert "crypto.com" in text  # URL host reduced
    assert "co.mona.android" not in text  # mobile app id is not a domain pattern
    # amass's own loader consumes it and matches correctly
    scope = _load_scope()
    assert scope is not None
    in_p, out_p = scope
    assert _in_scope("api.crypto.com", in_p, out_p) is True
    assert _in_scope("crypto.com", in_p, out_p) is True
    assert _in_scope("evil.com", in_p, out_p) is False


def test_manifest_cached_to_disk(loaded_manifest):
    m, tmp_path = loaded_manifest
    cache = tmp_path / "scope" / "crypto.json"
    assert cache.is_file()
    cached = json.loads(cache.read_text())
    assert cached["counts"]["in_scope"] == 3


def test_load_uses_cache_when_present(monkeypatch, tmp_path):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    # write a fake cache
    fake = {"handle": "crypto", "fetched_at": 0, "in_scope": [], "out_of_scope_assets": [],
            "excluded_categories": [], "weaknesses": [], "policy": "", "counts": {}}
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    (scope_dir / "crypto.json").write_text(json.dumps(fake))
    with mock.patch.object(ps, "_get") as g:  # _get must NOT be called
        m = ps.load_program_scope("crypto", refresh=False)
    assert g.call_count == 0
    assert m["_cache"] == "hit"


# --- check_scope -------------------------------------------------------------

def test_check_scope_in_wildcard(loaded_manifest):
    r = ps.check_scope("api.crypto.com", handle="crypto")
    assert r["in_scope"] is True
    assert r["matched_asset"]["asset_type"] == "WILDCARD"
    assert r["max_severity"] == "critical"


def test_check_scope_in_url_path(loaded_manifest):
    r = ps.check_scope("https://crypto.com/exchange/BTC", handle="crypto")
    assert r["in_scope"] is True
    assert r["matched_asset"]["asset_identifier"] == "https://crypto.com/exchange"


def test_check_scope_out_of_scope_asset(loaded_manifest):
    r = ps.check_scope("com.defi.wallet", handle="crypto")
    assert r["in_scope"] is False
    assert "out-of-scope" in r["reason"]


def test_check_scope_no_match(loaded_manifest):
    r = ps.check_scope("evil.example.com", handle="crypto")
    assert r["in_scope"] is False
    assert "no matching asset" in r["reason"]


# --- check_reportable --------------------------------------------------------

def test_check_reportable_excluded(loaded_manifest):
    r = ps.check_reportable("Missing security headers", handle="crypto")
    assert r["reportable"] is False
    assert r["exclusion_hit"] is not None
    assert "headers" in r["reason"].lower()


def test_check_reportable_brute_force_excluded(loaded_manifest):
    r = ps.check_reportable("Brute force", handle="crypto")
    assert r["reportable"] is False
    assert r["exclusion_hit"] is not None


def test_check_reportable_clean_cwe(loaded_manifest):
    r = ps.check_reportable("CWE-89", handle="crypto")
    assert r["reportable"] is True
    assert r["exclusion_hit"] is None
    assert r["weakness_match"] is not None
    assert r["weakness_match"]["external_id"] == "cwe-89"


def test_check_reportable_unknown_cwe(loaded_manifest):
    r = ps.check_reportable("CWE-999", handle="crypto")
    assert r["reportable"] is True       # not in exclusions -> reportable (just unknown CWE)
    assert r["weakness_match"] is None   # not in the weakness allowlist


# --- auth path ---------------------------------------------------------------

def test_no_credentials_returns_auth_required(monkeypatch, tmp_path):
    monkeypatch.delenv("H1_API_USERNAME", raising=False)
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    _, err = ps._build_manifest("crypto")
    assert "auth_required" in err


# --- program_hacktivity ------------------------------------------------------

def test_hacktivity_mocked(loaded_manifest):
    with mock.patch.object(ps, "_get", side_effect=_mock_get):
        r = ps.program_hacktivity("crypto", limit=5)
    assert r["status"] == "ok"
    assert r["count"] == 2
    # Disclosed item (id 1)
    disclosed = [x for x in r["reports"] if x["disclosed"]][0]
    assert disclosed["title"] == "SSRF in avatar upload"
    assert disclosed["severity"] == "high"
    assert disclosed["reporter"] == "testuser"
    assert disclosed["latest_disclosable_action"] == "Activities::BugResolved"
    # Undisclosed item (id 3981275) — title/substate/url are null but
    # always-present fields are extracted.
    undisclosed = [x for x in r["reports"] if not x["disclosed"]][0]
    assert undisclosed["title"] is None
    assert undisclosed["disclosed"] is False
    assert undisclosed["votes"] == 3
    assert undisclosed["reporter"] == "p4p3r_hak"
    assert undisclosed["latest_disclosable_action"] == "Activities::BountyAwarded"
    assert undisclosed["submitted_at"] == "2026-08-30T21:50:43.500Z"
    assert undisclosed["latest_disclosable_activity_at"] == "2026-09-03T08:23:59.873Z"


def test_hacktivity_filter_ignored_warning(loaded_manifest):
    """T-005 (a): filtered=0 + bare>0 → warning present."""
    with mock.patch.object(ps, "_get", side_effect=_mock_get) as m:
        r = ps.program_hacktivity("crypto", query="severity_rating:high", limit=10)
    assert r["status"] == "ok"
    assert r["count"] == 0
    assert "warning" in r
    assert "do NOT read 0 as 'no dupes'" in r["warning"]
    # The extra bare re-probe was fired (2 calls: filtered + bare).
    assert m.call_count == 2


def test_hacktivity_filter_genuine_zero(loaded_manifest):
    """T-005 (b): filtered=0 + bare=0 → no warning."""
    # Patch _get to always return empty data for both filtered and bare.
    def _empty(path, params=None, **kw):
        return (200, {"data": []})
    with mock.patch.object(ps, "_get", side_effect=_empty) as m:
        r = ps.program_hacktivity("crypto", query="severity_rating:high", limit=10)
    assert r["status"] == "ok"
    assert r["count"] == 0
    assert "warning" not in r
    # The extra bare re-probe was still fired (2 calls) but bare also 0.
    assert m.call_count == 2


def test_hacktivity_no_extra_probe_on_results(loaded_manifest):
    """T-005 (c): non-empty filtered results → no extra probe fired."""
    # Patch _get to return results even for filtered queries.
    def _always_results(path, params=None, **kw):
        return (200, {"data": [
            {"id": 99, "type": "hacktivity_item", "attributes": {
                "title": "XSS", "substate": "Resolved", "severity_rating": "high",
                "cwe": "XSS", "url": "https://hackerone.com/reports/99",
                "disclosed_at": "2026-09-01T00:00:00Z", "disclosed": True,
                "submitted_at": "2026-08-01T00:00:00Z",
                "latest_disclosable_action": "Activities::BugResolved",
                "latest_disclosable_activity_at": "2026-09-01T00:00:00Z",
                "votes": 5, "total_awarded_amount": 200},
                "relationships": {"reporter": {"data": {"type": "user",
                 "attributes": {"username": "hunter1"}}}}},
        ]})
    with mock.patch.object(ps, "_get", side_effect=_always_results) as m:
        r = ps.program_hacktivity("crypto", query="severity_rating:high", limit=10)
    assert r["status"] == "ok"
    assert r["count"] == 1
    assert "warning" not in r
    # Only 1 call — no bare re-probe because filtered returned results.
    assert m.call_count == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


# --- regression: OOS precedence & required-handle guards ---------------------

def test_check_scope_oos_wins_over_wildcard(loaded_manifest, monkeypatch, tmp_path):
    """REGRESSION (bugcheck 2026-09-12): selfservice.grindr.com is explicitly
    OOS under *.grindr.com but used to return in_scope=True because the
    wildcard match short-circuited before the OOS list was consulted."""
    m, _ = loaded_manifest
    m["out_of_scope_assets"] = [{
        "id": "9", "asset_type": "DOMAIN", "asset_identifier": "mail.crypto.com",
        "eligible_for_bounty": False, "eligible_for_submission": False,
        "max_severity": "none", "instruction": "legacy OOS host shadowing the in-scope wildcard",
        "reference": None, "updated_at": "2026-01-01T00:00:00Z"}]
    # check_scope reads from the on-disk cache, so persist the mutation.
    ps._save_cache("crypto", m)
    r = ps.check_scope("mail.crypto.com", handle="crypto")
    assert r["in_scope"] is False
    assert "out-of-scope" in r["reason"]
    # non-shadowed host still matches the in-scope wildcard
    assert ps.check_scope("api.crypto.com", handle="crypto")["in_scope"] is True


def test_check_scope_oos_exact_beats_url_asset(loaded_manifest):
    m, _ = loaded_manifest
    m["out_of_scope_assets"] = [{
        "id": "9", "asset_type": "URL",
        "asset_identifier": "https://crypto.com/exchange",
        "eligible_for_submission": False, "max_severity": "none",
        "instruction": "legacy path OOS"}]
    # check_scope reads from the on-disk cache, so persist the mutation.
    ps._save_cache("crypto", m)
    r = ps.check_scope("https://crypto.com/exchange/BTC", handle="crypto")
    assert r["in_scope"] is False


def test_check_scope_handle_required():
    with pytest.raises(ValueError):
        ps.check_scope("crypto.com", handle="")
    with pytest.raises(ValueError):
        ps.check_scope("crypto.com", handle="   ")


def test_check_reportable_handle_required():
    with pytest.raises(ValueError):
        ps.check_reportable("CWE-89", handle="")


def test_in_scope_oos_exclamation_pattern(monkeypatch, tmp_path):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkey = tmp_path / ".scope"
    monkey.write_text("*.crypto.com\n!selfservice.crypto.com\n")
    scope = _load_scope()
    assert scope is not None
    in_p, out_p = scope
    assert _in_scope("api.crypto.com", in_p, out_p) is True
    assert _in_scope("selfservice.crypto.com", in_p, out_p) is False
    assert _in_scope("evil.com", in_p, out_p) is False
