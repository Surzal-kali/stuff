"""Regression tests for the operator-armed scope gate (utils/scope_gate.py).

The gate prevents traffic-sending tools from firing at out-of-scope hosts
when a bug-bounty scope is armed from the Tool REPL.  These tests are fully
self-contained: a synthetic manifest is injected (no H1/Bugcrowd/Intigriti
fetch), the armed-state file is redirected to tmp_path, reverse-DNS is
stubbed, and every live connection / subprocess point is stubbed — so
nothing touches the network or the real ``scope/`` dir and no real scan,
SSH/SMB connection, or raw socket ever fires.

Covers:
- check_send  (packetcraft): None / non-routable allowed; IP tiers.
- check_scan  (scan tools): URL / host / IP / CIDR / range / list shapes;
  OOS-wins-over-wildcard; broad-range containment; strict vs non-strict;
  empty-target refusal.
- Operator allowlist override (CDN-safe blessing).
- Reverse-DNS attribution (in-scope hit + OOS-wins).
- Enforcement: every traffic-sending tool RAISES ScopeGateError on a blocked
  target (before any connection/subprocess) and passes when disarmed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

import utils.scope_gate as g
from utils.scope_gate import ScopeGateError

ROOT = Path(__file__).resolve().parent.parent


# --- helpers ---------------------------------------------------------------

def _load_isolated(rel_path: str, modname: str):
    """Load a payloads/ module directly, bypassing payloads/__init__ (whose
    load_dotenv() on a root-owned .env would PermissionError for a non-root
    runner). Returns the module or None on failure."""
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(modname, str(ROOT / rel_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        sys.modules.pop(modname, None)
        return None


def _arm(**kw):
    return g.arm("synthetic", "h1", **kw)


def _blocked_raises(call: Callable) -> bool:
    """True iff ``call`` raises ScopeGateError (the legal-butt block)."""
    try:
        call()
        return False
    except ScopeGateError as e:
        return "scope gate" in str(e).lower()
    except Exception as e:  # pragma: no cover - diagnostic only
        pytest.fail(f"expected ScopeGateError, got {type(e).__name__}: {e}")


def _not_gated(call: Callable) -> bool:
    """True iff the gate did NOT block (disarmed): anything but ScopeGateError."""
    try:
        call()
        return True
    except ScopeGateError:
        return False
    except Exception:
        return True  # a non-scope error means the gate let it through


@pytest.fixture
def scope(monkeypatch, tmp_path):
    """Isolate the gate: synthetic manifest, temp state file, no reverse DNS.

    In-scope: *.tesla.com + tesla.com + CIDR 198.51.100.0/24.
    Out-of-scope: feedback.tesla.com + CIDR 203.0.113.0/24.
    """
    manifest: Dict[str, Any] = {
        "handle": "synthetic",
        "platform": "h1",
        "in_scope": [
            {"asset_type": "WILDCARD", "asset_identifier": "*.tesla.com"},
            {"asset_type": "DOMAIN", "asset_identifier": "tesla.com"},
            {"asset_type": "CIDR", "asset_identifier": "198.51.100.0/24"},
        ],
        "out_of_scope_assets": [
            {"asset_type": "DOMAIN", "asset_identifier": "feedback.tesla.com"},
            {"asset_type": "CIDR", "asset_identifier": "203.0.113.0/24"},
        ],
    }
    monkeypatch.setattr(g, "_load_manifest", lambda h, p: manifest)
    monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: [])
    monkeypatch.setattr(g, "_state_path", lambda: tmp_path / ".armed_scope.json")
    g.disarm()
    g._CACHE["mtime"] = None
    g._CACHE["state"] = None
    yield manifest
    g.disarm()
    g._CACHE["mtime"] = None
    g._CACHE["state"] = None


# --- gate logic: check_scan / check_send -----------------------------------

class TestGateLogic:
    def test_disarmed_allows_everything(self, scope):
        assert g.check_scan("evil.example.com")[0]
        assert g.check_send("8.8.8.8")[0]

    def test_armed_empty_target_refuses(self, scope):
        _arm()
        ok, reason = g.check_scan("")
        assert not ok and "empty target" in reason.lower()

    def test_in_scope_hostname_allows(self, scope):
        _arm()
        assert g.check_scan("www.tesla.com")[0]

    def test_oos_hostname_refuses(self, scope):
        _arm()
        ok, reason = g.check_scan("feedback.tesla.com")
        assert not ok and "out-of-scope" in reason.lower()

    def test_unrelated_hostname_refuses_strict(self, scope):
        _arm()
        assert not g.check_scan("evil.example.com")[0]

    def test_unrelated_hostname_nonstrict_allows(self, scope):
        _arm(strict=False)
        ok, reason = g.check_scan("evil.example.com")
        assert ok and "warning" in reason.lower()

    def test_url_in_scope(self, scope):
        _arm()
        assert g.check_scan("https://www.tesla.com/login")[0]

    def test_url_oos(self, scope):
        _arm()
        assert not g.check_scan("http://feedback.tesla.com/x")[0]

    def test_service_url_hydra_shape(self, scope):
        _arm()
        assert g.check_scan("ssh://www.tesla.com:22")[0]
        assert not g.check_scan("ssh://feedback.tesla.com:22")[0]

    def test_in_scope_cidr_asset_allows(self, scope):
        _arm()
        assert g.check_scan("198.51.100.5")[0]

    def test_oos_cidr_refuses(self, scope):
        _arm()
        assert not g.check_scan("203.0.113.5")[0]

    def test_broad_cidr_outside_scope_refuses(self, scope):
        _arm()
        ok, reason = g.check_scan("10.0.0.0/24")
        assert not ok and "broad" in reason.lower()

    def test_broad_cidr_within_inscope_asset_allows(self, scope):
        _arm()
        assert g.check_scan("198.51.100.0/28")[0]  # subnet of the in-scope /24

    def test_hyphen_range_refuses(self, scope):
        _arm()
        ok, reason = g.check_scan("10.0.0.1-50")
        assert not ok and "range" in reason.lower()

    def test_hostname_with_year_is_not_a_range(self, scope):
        """F-4: digit-hyphen-digit HOSTNAMES must fall through to hostname
        matching instead of being broadly refused as nmap ranges."""
        assert not g._is_hyphen_range("wordpress-2024.example.com")
        assert not g._is_hyphen_range("s3-2024.example.com")
        assert not g._is_hyphen_range("co-uk")
        # real numeric nmap ranges still classify as ranges
        assert g._is_hyphen_range("10.0.0.1-50")
        assert g._is_hyphen_range("10.0.0.1-10.0.0.25")
        assert g._is_hyphen_range("1-50")
        # end-to-end: an in-scope hostname that merely contains a year now
        # resolves via the wildcard (was: refused as uncheckable range).
        _arm()
        assert g.check_scan("s3-2024.tesla.com")[0]

    def test_list_one_oos_refuses_whole(self, scope):
        _arm()
        assert not g.check_scan("www.tesla.com feedback.tesla.com")[0]

    def test_list_all_in_scope_allows(self, scope):
        _arm()
        assert g.check_scan("www.tesla.com api.tesla.com")[0]

    def test_allowlist_override_allows_ip(self, scope):
        _arm()
        assert not g.check_send("8.8.8.8")[0]          # unconfirmed -> refuse
        g.add_ip("8.8.8.8", "dns.google")
        assert g.check_send("8.8.8.8")[0]              # blessed -> allow

    def test_reverse_dns_in_scope_allows(self, scope, monkeypatch):
        monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: ["www.tesla.com"])
        # F-5: tier-3 now forward-confirms — stub the A lookup so the test
        # stays offline and deterministic.
        monkeypatch.setattr(g.socket, "gethostbyname", lambda host: "1.2.3.4")
        _arm()
        assert g.check_scan("1.2.3.4")[0]

    def test_reverse_dns_oos_wins(self, scope, monkeypatch):
        monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: ["feedback.tesla.com"])
        _arm()
        assert not g.check_scan("1.2.3.4")[0]

    def test_reverse_dns_in_scope_forward_confirmed_allows(self, scope, monkeypatch):
        """F-5: tier-3 auto-allow requires the PTR name to resolve back to
        the scanned IP (forward-confirmation)."""
        monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: ["www.tesla.com"])
        monkeypatch.setattr(g.socket, "gethostbyname", lambda host: "1.2.3.4")
        _arm()
        assert g.check_scan("1.2.3.4")[0]

    def test_reverse_dns_unconfirmed_ptr_refuses(self, scope, monkeypatch):
        """F-5: an in-scope PTR name that does NOT forward-confirm must not
        auto-allow — attacker-settable attribution falls through to the
        strict refuse."""
        monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: ["www.tesla.com"])

        def _no_resolver(host):
            raise OSError("stub: resolver unavailable")

        monkeypatch.setattr(g.socket, "gethostbyname", _no_resolver)
        _arm()
        ok, reason = g.check_scan("1.2.3.4")
        assert not ok

    def test_reverse_dns_wrong_forward_ip_refuses(self, scope, monkeypatch):
        """F-5: PTR name resolves, but to a different IP — no auto-allow."""
        monkeypatch.setattr(g, "_reverse_dns", lambda ip, timeout=2.0: ["www.tesla.com"])
        monkeypatch.setattr(g.socket, "gethostbyname", lambda host: "203.0.113.99")
        _arm()
        assert not g.check_scan("1.2.3.4")[0]

    def test_send_none_allows(self, scope):
        _arm()
        assert g.check_send(None)[0]

    def test_send_non_routable_not_gated(self, scope):
        _arm()
        for ip in ("255.255.255.255", "127.0.0.1", "169.254.1.1",
                   "224.0.0.251", "0.0.0.0"):
            assert g.check_send(ip)[0], ip

    def test_nonstrict_broad_allows(self, scope):
        _arm(strict=False)
        assert g.check_scan("10.0.0.0/24")[0]

    def test_arm_requires_manifest(self, scope, monkeypatch):
        monkeypatch.setattr(g, "_load_manifest", lambda h, p: None)
        res = g.arm("nope", "h1")
        assert not res["ok"] and "manifest" in res["error"].lower()

    def test_disarm_restores_lab_mode(self, scope):
        _arm()
        assert not g.check_scan("evil.example.com")[0]
        g.disarm()
        assert g.check_scan("evil.example.com")[0]


# --- IPv6 gap (F-3): crafted v6 packets must yield a real, gated dst -------

class TestIPv6Gap:
    """An IPv6 destination must reach the gate instead of silently passing
    as an ungated (None/garbage) destination."""

    def test_v6_dst_extracted(self, scope):
        pytest.importorskip("scapy")
        import utils.packetcraft as p
        pkt = p.IPv6(dst="2001:db8::1") / p.TCP(sport=1, dport=80, flags="S")
        assert p._packet_dst(pkt) == "2001:db8::1"

    def test_v6_hex_roundtrip(self, scope):
        """Bare IPv6 hex must not garbage-misparse as IPv4 (old path returned
        a bogus '0.0.0.0' dst that the gate treated as non-routable)."""
        pytest.importorskip("scapy")
        import utils.packetcraft as p
        pkt = p.IPv6(dst="2001:db8::1") / p.TCP(sport=1, dport=80, flags="S")
        pkt2 = p._packet_from_hex(p._packet_to_hex(pkt))
        assert p._packet_dst(pkt2) == "2001:db8::1"

    def test_v6_target_gated_when_armed(self, scope):
        """Armed + unconfirmed v6 destination -> refused (strict)."""
        pytest.importorskip("scapy")
        import utils.packetcraft as p
        _arm()
        ok, reason = g.check_send("2001:db8::1")
        assert not ok


# --- enforcement: tools raise ScopeGateError on block ----------------------

def _fake_launch(command, *, tool_name, timeout=1800.0, log_dir=None,
                 verdict_parser=None, env=None):
    return {"job_id": "fake", "tool": tool_name, "status": "running",
            "log_file": "", "started": 0, "message": "(stubbed)"}


class _BoomConn:
    def __init__(self, *a, **k):
        raise OSError("stub: no real SMB connection")


class _FakeSSH:
    def set_missing_host_key_policy(self, *a):
        pass

    def connect(self, *a, **k):
        raise OSError("stub: no real ssh")

    def close(self):
        pass

    def exec_command(self, *a, **k):
        raise OSError("stub")


class _FakeLib:
    def raw_syn_scan(self, *a):
        return 0


@pytest.fixture
def tools(scope, monkeypatch):
    """Import the traffic-sending tool modules and stub their live points so
    the gate-PASSED path never fires real traffic."""
    import auxiliaries.nmap as nmap
    import auxiliaries.masscan as masscan
    import auxiliaries.impacket_suite as imp
    import auxiliaries.smb_scanner as smb
    import utils.paramiko_client as pc
    import utils.packetcraft as p
    # F-2: self-contained load — same isolation pattern ffuf/hydra use.  A
    # box missing the frameit build artifact now SKIPS the enforcement tests
    # instead of erroring the whole fixture at import time.
    rs = _load_isolated("listeners/raw_scan.py", "listeners.raw_scan")
    if rs is None:
        pytest.skip("raw_scan unavailable (frameit.so build artifact missing)")
    monkeypatch.setattr(nmap, "launch_job", _fake_launch)
    monkeypatch.setattr(masscan, "launch_job", _fake_launch)
    monkeypatch.setattr(imp, "SMBConnection", _BoomConn)
    monkeypatch.setattr(smb, "SMBConnection", _BoomConn)
    monkeypatch.setattr(pc.paramiko, "SSHClient", _FakeSSH)
    monkeypatch.setattr(rs, "load_lib", lambda: _FakeLib())
    pkt_hex = p._packet_to_hex(
        p._craft().icmp_echo_request("10.0.0.1", "203.0.113.7", b"x"))
    return type("T", (), dict(nmap=nmap, masscan=masscan, imp=imp, smb=smb,
                             pc=pc, pkt=p, rs=rs, hex=pkt_hex))()


class TestEnforcement:
    """Every traffic-sending tool must raise ScopeGateError on a blocked
    target BEFORE any real connection/subprocess, and pass when disarmed."""

    def test_block_then_disarm_toggle(self, tools):
        _arm()
        assert _blocked_raises(lambda: tools.nmap.run_nmap("feedback.tesla.com", "-Pn"))
        g.disarm()
        assert _not_gated(lambda: tools.nmap.run_nmap("feedback.tesla.com", "-Pn"))

    @pytest.mark.parametrize("label,call", [
        ("nmap", lambda t: t.nmap.run_nmap("feedback.tesla.com", "-Pn")),
        ("masscan_broad", lambda t: t.masscan.run_masscan("203.0.113.0/24", ports="80")),
        ("impacket_smb_enum", lambda t: t.imp.smb_enum_shares("feedback.tesla.com")),
        ("impacket_smb_read", lambda t: t.imp.smb_read_file("feedback.tesla.com", "C$", "x")),
        ("impacket_secretsdump", lambda t: t.imp.secretsdump("feedback.tesla.com", "u", "p")),
        ("impacket_psexec", lambda t: t.imp.psexec_exec("feedback.tesla.com", "whoami", "u", "p")),
        ("impacket_wmiexec", lambda t: t.imp.wmiexec_exec("feedback.tesla.com", "whoami", "u", "p")),
        ("impacket_atexec", lambda t: t.imp.atexec_exec("feedback.tesla.com", "whoami", "u", "p")),
        ("smb_null_session", lambda t: t.smb.SMBScanner().check_null_session("feedback.tesla.com")),
        ("ssh_connect", lambda t: t.pc.ssh_connect("feedback.tesla.com", "u", "p")),
        ("paramiko_oneshot", lambda t: t.pc.paramiko_client("feedback.tesla.com", "u", "p", "id")),
        ("raw_syn_scan", lambda t: t.rs.syn_scan("203.0.113.9", 80)),
        ("packetcraft_send", lambda t: t.pkt.send_packet(t.hex, 1, "lo")),
    ])
    def test_blocked_raises_scopegate(self, tools, label, call):
        _arm()
        assert _blocked_raises(lambda: call(tools)), f"{label} did not raise ScopeGateError"

    @pytest.mark.parametrize("label,call", [
        ("nmap", lambda t: t.nmap.run_nmap("feedback.tesla.com", "-Pn")),
        ("impacket_smb_enum", lambda t: t.imp.smb_enum_shares("feedback.tesla.com")),
        ("ssh_connect", lambda t: t.pc.ssh_connect("feedback.tesla.com", "u", "p")),
        ("raw_syn_scan", lambda t: t.rs.syn_scan("203.0.113.9", 80)),
        ("packetcraft_send", lambda t: t.pkt.send_packet(t.hex, 1, "lo")),
    ])
    def test_disarmed_not_gated(self, tools, label, call):
        g.disarm()
        assert _not_gated(lambda: call(tools)), f"{label} wrongly gated when disarmed"

    def test_ssh_exec_gates_on_session_hostname(self, tools):
        _arm()
        from utils.session_manager import get_manager
        from utils.handles import format_handle
        sm = get_manager()
        sid = sm.register("ssh", "u@feedback.tesla.com:22", _FakeSSH(),
                          hostname="feedback.tesla.com")
        h = format_handle("ssh", sid)
        try:
            assert _blocked_raises(lambda: tools.pc.ssh_exec(h, "id"))
            assert _blocked_raises(lambda: tools.pc.ssh_shell(h, "id"))
        finally:
            sm.close(sid)


# --- ffuf / hydra: load directly (bypass payloads/__init__); skip if absent -

_ffuf = _load_isolated("payloads/ffuf.py", "_regr_ffuf")
_hydra = _load_isolated("payloads/hydra.py", "_regr_hydra")


@pytest.mark.skipif(_ffuf is None, reason="ffuf module not importable")
def test_ffuf_blocked_raises(scope, monkeypatch):
    monkeypatch.setattr(_ffuf, "launch_job", _fake_launch)
    _arm()
    assert _blocked_raises(lambda: _ffuf.run_ffuf("http://feedback.tesla.com/FUZZ"))


@pytest.mark.skipif(_ffuf is None, reason="ffuf module not importable")
def test_ffuf_disarmed_not_gated(scope, monkeypatch):
    monkeypatch.setattr(_ffuf, "launch_job", _fake_launch)
    g.disarm()
    assert _not_gated(lambda: _ffuf.run_ffuf("http://feedback.tesla.com/FUZZ"))


@pytest.mark.skipif(_hydra is None, reason="hydra module not importable")
def test_hydra_blocked_raises(scope, monkeypatch):
    monkeypatch.setattr(_hydra, "launch_job", _fake_launch)
    _arm()
    assert _blocked_raises(lambda: _hydra.run_hydra("ssh://feedback.tesla.com:22", "-l a -p b"))


@pytest.mark.skipif(_hydra is None, reason="hydra module not importable")
def test_hydra_disarmed_not_gated(scope, monkeypatch):
    monkeypatch.setattr(_hydra, "launch_job", _fake_launch)
    g.disarm()
    assert _not_gated(lambda: _hydra.run_hydra("ssh://feedback.tesla.com:22", "-l a -p b"))
