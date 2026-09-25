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
- send_and_receive_packet (packetcraft): gate BEFORE the probe fires; reply
  captured in the same call.
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
import types
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
        import auxiliaries.program_scope as _ps

        monkeypatch.setattr(g, "_load_manifest", lambda h, p: None)
        # arm() consults the program-scope cache layer (and falls back to a
        # live fetch) before refusing; stub both so the test stays hermetic -
        # no filesystem, no HackerOne API, no .env auto-load side effects
        # (program_scope runs load_dotenv(override=True) at import).
        monkeypatch.setattr(_ps, "_load_cache", lambda h, p: None)
        monkeypatch.setattr(_ps, "load_program_scope", lambda *a, **k: None)
        res = g.arm("nope", "h1")
        assert not res["ok"] and "manifest" in res["error"].lower()

    def test_scope_cache_path_survives_unwritable_workspace(self, monkeypatch):
        """Regression (2026-09-25): _scope_cache_path used to mkdir() the
        workspace scope dir unconditionally, so an unwritable WORKSPACE_ROOT
        (sandboxed seat / stale .env pointing at another user's home) crashed
        arm() with a raw PermissionError instead of degrading to a cache
        miss."""
        import tempfile

        import auxiliaries.program_scope as _ps

        monkeypatch.setenv("WORKSPACE_ROOT", "/proc/definitely-not-writable")
        p = _ps._scope_cache_path("synthetic", "h1")
        fallback_root = Path(tempfile.gettempdir()) / "framework-scope-cache"
        assert str(p).startswith(str(fallback_root)), p
        assert p.parent.is_dir(), p

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
    # send_and_receive_packet: stub the live sr1/srp1 points so the
    # gate-PASSED path never opens a real raw socket or fires a probe.
    monkeypatch.setattr(p, "sr1", lambda pkt, **kw: None)
    monkeypatch.setattr(p, "srp1", lambda pkt, **kw: None)
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
        ("packetcraft_send_and_receive",
         lambda t: t.pkt.send_and_receive_packet(t.hex, 5, "lo")),
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
        ("packetcraft_send_and_receive",
         lambda t: t.pkt.send_and_receive_packet(t.hex, 5, "lo")),
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


# --- send_and_receive_packet: gate-before-probe + reply capture -------------
# (2026-09-19) "send and forget" only covers probes that need no answer;
# sr1/srp1 close the loop in ONE gated call. Stub points: p.sr1 / p.srp1
# (module-level imports from scapy.all) — nothing real ever fires.

@pytest.fixture
def sndrcv(scope, monkeypatch):
    """packetcraft with sr1/srp1 stubbed; canned reply + call recorder."""
    pytest.importorskip("scapy")
    import utils.packetcraft as p
    calls: Dict[str, list] = {"sr1": [], "srp1": []}
    canned: Dict[str, Any] = {"reply": None}

    def _fake_sr1(pkt, **kw):
        calls["sr1"].append((pkt, kw))
        return canned["reply"]

    def _fake_srp1(pkt, **kw):
        calls["srp1"].append((pkt, kw))
        return canned["reply"]

    monkeypatch.setattr(p, "sr1", _fake_sr1)
    monkeypatch.setattr(p, "srp1", _fake_srp1)
    return type("S", (), dict(p=p, calls=calls, canned=canned))()


class TestSendAndReceive:
    """The probe must be gate-checked BEFORE firing (identical placement to
    send_packet) and its reply must come back in the same call envelope."""

    def _icmp_echo_hex(self, s, dst="203.0.113.7"):
        return s.p._packet_to_hex(
            s.p._craft().icmp_echo_request("10.0.0.1", dst, b"x"))

    def test_blocked_raises_before_any_probe(self, sndrcv):
        _arm()
        assert _blocked_raises(
            lambda: sndrcv.p.send_and_receive_packet(
                self._icmp_echo_hex(sndrcv), 5, "lo"))
        assert sndrcv.calls == {"sr1": [], "srp1": []}  # no probe left the box

    def test_in_scope_reply_envelope(self, sndrcv):
        _arm()
        reply = sndrcv.p.IP(src="198.51.100.5", dst="10.0.0.1") / sndrcv.p.ICMP(type=0)
        sndrcv.canned["reply"] = reply
        out = sndrcv.p.send_and_receive_packet(
            self._icmp_echo_hex(sndrcv, dst="198.51.100.5"), 5, "lo")
        assert "Reply after" in out and "reply hex:" in out
        assert sndrcv.p._packet_to_hex(reply) in out
        assert len(sndrcv.calls["sr1"]) == 1 and not sndrcv.calls["srp1"]
        kw = sndrcv.calls["sr1"][0][1]
        assert kw.get("iface") == "lo" and kw.get("timeout") == 5
        # roundtrip: the reported reply hex re-parses to the same packet
        parsed = sndrcv.p._packet_from_hex(sndrcv.p._packet_to_hex(reply))
        assert sndrcv.p._packet_dst(parsed) == "10.0.0.1"

    def test_no_reply_envelope_when_disarmed(self, sndrcv):
        g.disarm()
        out = sndrcv.p.send_and_receive_packet(self._icmp_echo_hex(sndrcv), 5, "lo")
        assert "no reply within 5s" in out
        assert len(sndrcv.calls["sr1"]) == 1

    def test_l2_frame_routes_to_srp1(self, sndrcv):
        g.disarm()
        sndrcv.canned["reply"] = sndrcv.p.Ether() / sndrcv.p.ARP(op=2)
        frame = sndrcv.p._craft().craft_arp_request(
            "aa:bb:cc:dd:ee:ff", "10.0.0.1", "198.51.100.5")
        out = sndrcv.p.send_and_receive_packet(
            sndrcv.p._packet_to_hex(frame), 5, "lo")
        assert "Reply after" in out and len(sndrcv.calls["srp1"]) == 1
        assert not sndrcv.calls["sr1"]

    def test_broadcast_dhcp_not_gated_when_armed(self, sndrcv):
        _arm()
        sndrcv.canned["reply"] = None
        pkt = sndrcv.p._craft().dhcp_discover("aa:bb:cc:dd:ee:ff")
        out = sndrcv.p.send_and_receive_packet(
            sndrcv.p._packet_to_hex(pkt), 5, "lo")
        assert "no reply within 5s" in out
        assert len(sndrcv.calls["srp1"]) == 1  # broadcast: allowed, not gated

    def test_v6_probe_gated_when_armed(self, sndrcv):
        _arm()
        pkt = sndrcv.p.IPv6(dst="2001:db8::1") / sndrcv.p.TCP(
            sport=1, dport=80, flags="S")
        assert _blocked_raises(
            lambda: sndrcv.p.send_and_receive_packet(
                sndrcv.p._packet_to_hex(pkt), 5, "lo"))
        assert sndrcv.calls == {"sr1": [], "srp1": []}


# --- scope_gate add_host/remove_host: tier-1b blessed hostnames -------------
# (2026-09-19) Vhost lanes (e.g. ZAP raw send, whose connect target comes from
# the Host header) present HOSTNAMES the IP allowlist can never bless.  The
# operator blesses hostname->IP explicitly; the gate accepts the blessed
# hostname via tier-1b, never resolves DNS for it, and revocation is immediate
# (mtime-checked state).  NOTE: check_send only ever sees packet destination
# IPs, so hostname verdicts flow through check_scan -> _check_one.

class TestBlessedHosts:
    def test_add_host_requires_blessed_ip(self, scope):
        _arm()
        res = g.add_host("evil.example", "203.0.113.9")
        assert not res["ok"] and "allowlist" in res["error"].lower()

    def test_blessed_host_passes_and_normalizes(self, scope):
        _arm()
        g.add_ip("198.51.100.5", "vhost host")
        res = g.add_host("Earth.Example.com.", "198.51.100.5")
        assert res["ok"] and res["blessed_hosts"] == {"earth.example.com": "198.51.100.5"}
        ok, _ = g.check_scan("earth.example.com")
        assert ok
        ok, _ = g.check_scan("EARTH.Example.COM")
        assert ok
        # direct verdict names the tier (check_scan aggregates reasons)
        ok, reason = g._check_one("earth.example.com", g._load_state())
        assert ok and "blessed-host" in reason

    def test_unblessed_hostname_refused_strict(self, scope):
        _arm()
        ok, reason = g.check_scan("nope.example.com")
        assert not ok and "not confirmed in-scope" in reason and "add-host" in reason

    def test_remove_host_revokes(self, scope):
        _arm()
        g.add_ip("198.51.100.5", "x")
        g.add_host("foo.example.com", "198.51.100.5")
        assert g.check_scan("foo.example.com")[0]
        assert g.remove_host("foo.example.com")["ok"]
        assert not g.check_scan("foo.example.com")[0]

    def test_add_host_rejects_bad_shapes(self, scope):
        _arm()
        g.add_ip("198.51.100.5", "x")
        for bad in ("http://x.com", "a b.com", "198.51.100.5", "user@x.com", "x/y.com"):
            assert not g.add_host(bad, "198.51.100.5")["ok"], bad

    def test_status_reports_blessed_hosts(self, scope):
        _arm()
        g.add_ip("198.51.100.5", "x")
        g.add_host("foo.example.com", "198.51.100.5")
        assert g.status()["blessed_hosts_size"] == 1


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


# --- sqlmap / fastcgi / ssh_exec_batch / dispatch_metasploit: gate coverage -
# (2026-09-19) These four target-touching modules shipped WITHOUT gate checks;
# the tests below pin the fix: blocked target -> ScopeGateError BEFORE any
# subprocess/socket/RPC fires; disarmed -> the tool proceeds (live points
# stubbed, nothing real ever fires from the test).

_sqlmap = _load_isolated("payloads/sqlmap.py", "_regr_sqlmap")
_fastcgi = _load_isolated("payloads/fastcgi.py", "_regr_fastcgi")
_sshe = _load_isolated("auxiliaries/ssh_exec.py", "_regr_sshe")
_msf = None


def _load_msf_isolated():
    """Load metasploiting with a temporary dotenv stub.

    metasploiting calls ``load_dotenv`` at module level; on a root-0600 .env
    that PermissionErrors for non-root runners and _load_isolated would
    silently return None (test skipped). Stub dotenv for the exec, then
    restore the real module so nothing else in the session is masked.
    """
    if "_regr_msf" in sys.modules:
        return sys.modules["_regr_msf"]
    real_dotenv = sys.modules.get("dotenv")
    stub = types.ModuleType("dotenv")
    stub.load_dotenv = lambda *a, **k: None
    stub.dotenv_values = lambda *a, **k: {}
    sys.modules["dotenv"] = stub
    try:
        return _load_isolated("payloads/metasploiting.py", "_regr_msf")
    finally:
        if real_dotenv is not None:
            sys.modules["dotenv"] = real_dotenv
        else:
            sys.modules.pop("dotenv", None)


_msf = _load_msf_isolated()

_OOS = "feedback.tesla.com"     # out-of-scope in the synthetic manifest
_INS = "www.tesla.com"          # in-scope via the *.tesla.com wildcard
_OOS_IP = "203.0.113.9"         # out-of-scope CIDR 203.0.113.0/24


class _NoPopen:
    def __init__(self, *a, **k):
        raise OSError("stub: no real subprocess")


@pytest.mark.skipif(_sqlmap is None, reason="sqlmap module not importable")
def test_sqlmap_blocked_raises(scope, monkeypatch):
    monkeypatch.setattr(_sqlmap.subprocess, "Popen", _NoPopen)
    _arm()
    assert _blocked_raises(lambda: _sqlmap.run_sqlmap(f"http://{_OOS}/x?id=1"))


@pytest.mark.skipif(_sqlmap is None, reason="sqlmap module not importable")
def test_sqlmap_disarmed_not_gated(scope, monkeypatch):
    monkeypatch.setattr(_sqlmap.subprocess, "Popen", _NoPopen)
    g.disarm()
    assert _not_gated(lambda: _sqlmap.run_sqlmap(f"http://{_OOS}/x?id=1"))


@pytest.mark.skipif(_fastcgi is None, reason="fastcgi module not importable")
@pytest.mark.parametrize("tool", ["fastcgi_request", "fastcgi_php_exec"])
def test_fastcgi_blocked_raises(scope, tool):
    _arm()
    assert _blocked_raises(lambda: getattr(_fastcgi, tool)(_OOS_IP))


@pytest.mark.skipif(_fastcgi is None, reason="fastcgi module not importable")
def test_fastcgi_disarmed_not_gated(scope, monkeypatch):
    monkeypatch.setattr(
        _fastcgi, "_fastcgi_send", lambda *a, **k: {"stdout": "stub"})
    g.disarm()
    assert _not_gated(lambda: _fastcgi.fastcgi_request(_OOS_IP))


@pytest.mark.skipif(_sshe is None, reason="ssh_exec module not importable")
def test_ssh_exec_batch_blocked_raises(scope, monkeypatch):
    monkeypatch.setattr(_sshe.paramiko, "SSHClient", _FakeSSH)
    _arm()
    assert _blocked_raises(
        lambda: _sshe.ssh_exec_batch(_OOS, "u", "p", ["id"]))


@pytest.mark.skipif(_sshe is None, reason="ssh_exec module not importable")
def test_ssh_exec_batch_disarmed_not_gated(scope, monkeypatch):
    monkeypatch.setattr(_sshe.paramiko, "SSHClient", _FakeSSH)
    g.disarm()
    assert _not_gated(lambda: _sshe.ssh_exec_batch(_OOS, "u", "p", ["id"]))


def _msf_client(monkeypatch):
    """MetasploitClient without __init__ (no RPC connect) + stubbed impl."""

    async def _fake_impl(self, *a, **k):
        return {"stdout": "stub", "status": "Success"}

    monkeypatch.setattr(
        _msf.MetasploitClient, "_execute_module_impl", _fake_impl)
    return _msf.MetasploitClient.__new__(_msf.MetasploitClient)


@pytest.mark.skipif(_msf is None, reason="metasploiting module not importable")
def test_msf_dispatch_blocked_raises(scope, monkeypatch):
    import asyncio

    client = _msf_client(monkeypatch)
    _arm()
    with pytest.raises(ScopeGateError):
        asyncio.run(client.dispatch_metasploit(
            "exploit/unix/ftp/vsftpd_234_backdoor", "exploit",
            {"RHOSTS": _OOS, "PAYLOAD": "cmd/unix/interact"}))


@pytest.mark.skipif(_msf is None, reason="metasploiting module not importable")
def test_msf_dispatch_missing_target_refused_when_armed(scope, monkeypatch):
    import asyncio

    client = _msf_client(monkeypatch)
    _arm()
    assert _blocked_raises(lambda: asyncio.run(client.dispatch_metasploit(
        "exploit/unix/ftp/vsftpd_234_backdoor", "exploit",
        {"PAYLOAD": "cmd/unix/interact"})))


@pytest.mark.skipif(_msf is None, reason="metasploiting module not importable")
def test_msf_dispatch_in_scope_passes_post_exempt(scope, monkeypatch):
    import asyncio

    client = _msf_client(monkeypatch)
    _arm()
    res = asyncio.run(client.dispatch_metasploit(
        "exploit/unix/ftp/vsftpd_234_backdoor", "exploit",
        {"RHOSTS": _INS, "PAYLOAD": "cmd/unix/interact"}))
    assert res.get("status") == "Success"
    # Post modules are session-bound (session origin was already gated) —
    # SESSION-only options must NOT hit the missing-target refusal.
    post = asyncio.run(client.dispatch_metasploit(
        "post/multi/gather/enum", "post", {"SESSION": "1"}))
    assert post.get("status") == "Success"


@pytest.mark.skipif(_msf is None, reason="metasploiting module not importable")
def test_msf_dispatch_disarmed_not_gated(scope, monkeypatch):
    import asyncio

    client = _msf_client(monkeypatch)
    g.disarm()
    assert _not_gated(lambda: asyncio.run(client.dispatch_metasploit(
        "exploit/unix/ftp/vsftpd_234_backdoor", "exploit",
        {"RHOSTS": _OOS, "PAYLOAD": "cmd/unix/interact"})))
