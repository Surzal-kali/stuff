"""Drift-guard tests for the operator-armed scope gate.

2026-09-20 fuzz-C finding: after an explicit re-arm with a narrowed IP
allowlist, a manifest hostname asset (earth.local) still PASSED the gate via
the tier-2 manifest match and the tool connected to the dropped host (one
refused SYN, zero data — but a gate PASS on an out-of-scope target).

These tests pin the fix:
- ``--ip-boundary``: tier-1b/2 hostname passes must forward-resolve into the
  operator's blessed IP set; unresolvable -> refused (fail-closed); partial
  resolution (one blessed, one not) -> refused.
- tier-3 PTR attribution is skipped for non-blessed IPs under the boundary.
- ``remove_ip`` cascades: blessed hostnames mapped to the removed IP are
  purged, so a dropped IP cannot stay alive through the vhost lane.
- a tier-1b mapping whose recorded IP left the allowlist no longer passes
  (belt re-check at verdict time).
- WITHOUT the boundary, program workflows are unchanged (manifest hostnames
  pass as before — CDN edges remain additive blessings).
"""

import pytest

import utils.scope_gate as g


def _manifest():
    return {
        "handle": "local-lab",
        "platform": "custom",
        "in_scope": [
            {"asset_type": "DOMAIN", "asset_identifier": "earth.local"},
            {"asset_type": "IP", "asset_identifier": "192.168.90.114"},
        ],
        "out_of_scope_assets": [],
    }


@pytest.fixture
def gate(monkeypatch, tmp_path):
    monkeypatch.setattr(g, "_load_manifest", lambda handle, platform: _manifest())
    monkeypatch.setattr(g, "_state_path", lambda: tmp_path / ".armed_scope.json")
    monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: [])
    g.disarm()
    g._CACHE["mtime"] = None
    g._CACHE["state"] = None
    yield g
    g.disarm()
    g._CACHE["mtime"] = None
    g._CACHE["state"] = None


def _arm_lab_ips(g):
    g.arm("local-lab", "custom")
    g.add_ip("192.168.90.114", "dummy .114")
    g.add_ip("192.168.90.116")
    g.add_ip("192.168.90.118")


def test_arm_persists_ip_boundary(gate):
    gate.arm("local-lab", "custom", ip_boundary=True)
    assert gate._load_state().get("ip_boundary") is True
    gate.arm("local-lab", "custom")
    assert gate._load_state().get("ip_boundary") is False


def test_no_boundary_manifest_hostname_still_passes(gate):
    """Regression: program workflows unchanged without the boundary."""
    _arm_lab_ips(gate)
    ok, why = gate.check_scan("http://earth.local/")
    assert ok, why


def test_boundary_hostname_outside_allowlist_refused(gate, monkeypatch):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    gate.add_ip("192.168.90.116")
    gate.add_ip("192.168.90.118")
    monkeypatch.setattr(
        g, "_resolved_ips", lambda host, timeout=2.0: ["192.168.90.115"]
    )
    ok, why = gate.check_scan("http://earth.local/")
    assert not ok, why
    assert "non-blessed IP(s)" in why and "192.168.90.115" in why


def test_boundary_hostname_inside_allowlist_passes(gate, monkeypatch):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    monkeypatch.setattr(
        g, "_resolved_ips", lambda host, timeout=2.0: ["192.168.90.114"]
    )
    ok, why = gate._check_one("earth.local", gate._load_state())
    assert ok, why
    assert "resolves to blessed IP" in why


def test_boundary_unresolvable_refused(gate, monkeypatch):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    monkeypatch.setattr(g, "_resolved_ips", lambda host, timeout=2.0: [])
    ok, why = gate.check_scan("earth.local")
    assert not ok, why
    assert "could not be resolved" in why


def test_boundary_partial_resolution_refused(gate, monkeypatch):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    monkeypatch.setattr(
        g,
        "_resolved_ips",
        lambda host, timeout=2.0: ["192.168.90.114", "203.0.113.9"],
    )
    ok, why = gate.check_scan("earth.local")
    assert not ok, why
    assert "203.0.113.9" in why


def test_boundary_skips_tier3_for_non_blessed_ips(gate, monkeypatch):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    # PTR would otherwise attribute a non-blessed IP into scope; the boundary
    # skips tier 3 entirely for IPs outside the operator's set.
    monkeypatch.setattr(
        g, "_reverse_dns", lambda ip, timeout=2.0: ["earth.local"]
    )
    ok, why = gate.check_scan("192.168.90.115")
    assert not ok, why


def test_remove_ip_cascades_blessed_hosts(gate):
    gate.arm("local-lab", "custom")
    gate.add_ip("192.168.90.115")
    gate.add_host("earth.local", "192.168.90.115")
    res = gate.remove_ip("192.168.90.115")
    assert res["ok"] and res["purged_blessed_hosts"] == ["earth.local"]
    state = gate._load_state()
    assert "earth.local" not in (state.get("blessed_hosts") or {})
    # The stale vhost no longer keeps the dropped IP alive via tier 1b; the
    # manifest tier still matches without a boundary (documented behavior).
    ok, _why = gate.check_scan("earth.local")
    assert ok  # no boundary armed: manifest asset passes as before


def test_tier1b_stale_mapping_does_not_pass_under_boundary(gate, monkeypatch):
    """A blessed hostname whose recorded IP left the allowlist must not keep
    it alive via tier 1b (belt: re-check the mapping at verdict time)."""
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.115")
    gate.add_host("earth.local", "192.168.90.115")
    # Simulate drift on an older state file: the IP leaves without the cascade.
    state = gate._load_state()
    state["allowlist"].pop("192.168.90.115")
    gate._write_state(state)
    monkeypatch.setattr(
        g, "_resolved_ips", lambda host, timeout=2.0: ["192.168.90.115"]
    )
    ok, why = gate.check_scan("earth.local")
    assert not ok, why


def test_tier1b_valid_mapping_still_passes(gate):
    gate.arm("local-lab", "custom", ip_boundary=True)
    gate.add_ip("192.168.90.114")
    gate.add_host("lab114.local", "192.168.90.114")
    ok, why = gate._check_one("lab114.local", gate._load_state())
    assert ok, why
    assert "blessed-host list" in why