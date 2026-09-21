"""Offline tests for the collaborator PUBLIC mode + ssrf_probe scan-config
backstop (zero-traffic; no listener sockets are started).

Covers the 2026-09-21 bounty-lab edits:
  - collab_generate subdomain vs public (COLLAB_PUBLIC_URL) modes
  - token-gated /r/<id>?to=<url> redirect decision matrix
  - callback store cap (public-internet scanner noise bound)
  - program_scope.get_armed_scan_config resolution + ssrf_probe._scan_config
    header merge (X-HackerOne-Research identification)
"""

from __future__ import annotations

import os
import tempfile
import time
from urllib.parse import quote

os.environ.setdefault("WORKSPACE_ROOT", tempfile.mkdtemp(prefix="collabtest_"))

import pytest

from listeners import collaborator as collab


@pytest.fixture()
def listener(monkeypatch):
    monkeypatch.setattr(collab, "_PUBLIC_BASE_URL", "")
    return collab.CollaboratorListener()


def test_generate_subdomain_mode(listener):
    gen = listener.generate()
    assert gen["mode"] == "subdomain"
    assert gen["base"] == ""
    assert gen["url"] == f"http://{gen['id']}.{collab._COLLAB_DOMAIN}/"
    assert gen["dns_name"] == f"{gen['id']}.{collab._COLLAB_DOMAIN}"
    assert gen["id"] in listener.active_ids


def test_generate_public_mode(listener, monkeypatch):
    monkeypatch.setattr(collab, "_PUBLIC_BASE_URL", "https://fun.example.ts.net")
    gen = listener.generate()
    assert gen["mode"] == "public"
    assert gen["base"] == "https://fun.example.ts.net"
    assert gen["url"] == f"https://fun.example.ts.net/c/{gen['id']}/"
    assert gen["id"] in listener.active_ids


def test_redirect_decision_matrix(listener):
    rid = "abc12xyz"
    listener.active_ids[rid] = 1.0
    # active id + http(s) target -> 302 with the decoded value
    path = f"/r/{rid}?to={quote('http://169.254.169.254/latest/meta-data/', safe='')}"
    status, location, out_id = listener.redirect_decision(path)
    assert (status, out_id) == ("302", rid)
    assert location == "http://169.254.169.254/latest/meta-data/"
    # unknown id -> 404 (no open redirector for the internet)
    assert listener.redirect_decision("/r/neverminted?to=http://x/")[0] == "404"
    # active id, no `to` -> 200 log-only callback
    assert listener.redirect_decision(f"/r/{rid}")[0] == "200"
    # non-http(s) `to` -> 200 (refused, not 302)
    assert listener.redirect_decision(f"/r/{rid}?to=file:///etc/passwd")[0] == "200"
    # not a redirect path at all
    assert listener.redirect_decision("/c/whatever/") == ("", "", "")
    assert listener.redirect_decision("/") == ("", "", "")


def test_redirect_decision_path_prefix(listener):
    """Funnel --set-path mounts: /collab/r/<id> must 302 like /r/<id>."""
    rid = "ab12cd34"
    listener.active_ids[rid] = 1.0
    path = f"/collab/r/{rid}?to={quote('https://169.254.169.254/', safe='')}"
    status, location, out_id = listener.redirect_decision(path)
    assert (status, out_id) == ("302", rid)
    assert location == "https://169.254.169.254/"
    # unknown id under a prefix still 404s (no open redirector)
    assert listener.redirect_decision("/collab/r/neverminted?to=http://x/")[0] == "404"
    # deep mounts and trailing slashes tolerated
    assert listener.redirect_decision(f"/owui/x/r/{rid}/")[0] == "200"


def test_store_cap_and_jsonl(listener, tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    for i in range(collab._STORE_CAP + 10):
        listener.store.add({"proto": "http", "ts": float(i), "path": f"/{i}"})
    kept = listener.store.poll(0.0)
    assert len(kept) == collab._STORE_CAP
    assert kept[-1]["path"] == f"/{collab._STORE_CAP + 9}"  # newest retained
    hits = tmp_path / "scope" / "collab_hits.jsonl"
    assert hits.is_file()  # durable evidence landed (append-only)
    lines = hits.read_text().strip().splitlines()
    assert len(lines) == collab._STORE_CAP + 10


def test_active_id_cap(listener):
    for i in range(collab._ACTIVE_ID_CAP + 50):
        listener.active_ids[f"id{i:06d}"] = float(i)
    listener.generate()
    assert len(listener.active_ids) <= collab._ACTIVE_ID_CAP


# --- program_scope.get_armed_scan_config + ssrf_probe._scan_config ----------


def test_get_armed_scan_config_resolves_state(monkeypatch, tmp_path):
    import json
    from auxiliaries import program_scope as ps

    scope_dir = tmp_path / "scope"
    scope_dir.mkdir(parents=True)
    (scope_dir / ".armed_packet_scope.json").write_text(json.dumps(
        {"handle": "cloudflare", "platform": "h1"}))
    (scope_dir / "cloudflare.json").write_text(json.dumps({"policy": "x"}))
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("H1_API_USERNAME", "surzvtr5h")

    cfg = ps.get_armed_scan_config()
    assert cfg is not None
    assert cfg["headers"]["X-HackerOne-Research"] == "surzvtr5h"
    assert cfg["platform"] == "h1" and cfg["handle"] == "cloudflare"


def test_get_armed_scan_config_none_when_disarmed(monkeypatch, tmp_path):
    from auxiliaries import program_scope as ps

    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "missing"))
    assert ps.get_armed_scan_config() is None


def test_ssrf_scan_config_merges_headers(monkeypatch):
    from auxiliaries import ssrf_probe

    monkeypatch.setattr(
        "auxiliaries.program_scope.get_armed_scan_config",
        lambda: {"headers": {"X-HackerOne-Research": "surzvtr5h"},
                 "max_requests_per_second": None},
        raising=False,
    )
    headers, rate = ssrf_probe._scan_config()
    assert headers["X-HackerOne-Research"] == "surzvtr5h"
    assert headers["User-Agent"] == "framework-ssrfprobe/1.0"
    assert rate is None


def test_ssrf_scan_config_fallback(monkeypatch):
    from auxiliaries import program_scope as ps
    from auxiliaries import ssrf_probe

    def _boom():
        raise RuntimeError("no armed state")

    monkeypatch.setattr(ps, "get_armed_scan_config", _boom)
    headers, rate = ssrf_probe._scan_config()
    assert headers == {"User-Agent": "framework-ssrfprobe/1.0"}
    assert rate is None