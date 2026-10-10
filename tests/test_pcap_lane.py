"""Tests for the pcap forensic lane in utils/packetcraft.py.

Covers save_pcap, load_pcap, list_pcaps — the batch save/load/list tools.
sniff_to_pcap requires root + raw sockets, so it's stubbed (scapy.sniff is
monkeypatched to return crafted packets without touching the wire).

All tests are self-contained: PCAP_DIR is redirected to a tmp_path, so no
real pcaps/ directory is touched and nothing writes to the repo root.
"""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
from typing import Any, Dict

import pytest

scapy = pytest.importorskip("scapy.all")

import utils.packetcraft as pc


# --- helpers ---------------------------------------------------------------

def _make_tcp_pkt() -> scapy.Packet:
    """A minimal valid IP/TCP packet for round-trip through hex."""
    return scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1234, dport=80, flags="S")


def _pkt_hex(pkt: scapy.Packet) -> str:
    return bytes(pkt).hex()


def _run(result: Any) -> str:
    """Extract the text from a tool result (these tools return strings)."""
    assert isinstance(result, str), f"expected str, got {type(result)}: {result}"
    return result


# --- save_pcap -------------------------------------------------------------

class TestSavePcap:
    def test_save_multi_packet(self, tmp_path, monkeypatch):
        """save_pcap writes a multi-packet pcap and reports the path."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        p1 = _make_tcp_pkt()
        p2 = scapy.IP(src="10.0.0.3", dst="10.0.0.4") / scapy.TCP(sport=80, dport=1234, flags="A")
        hexes = [_pkt_hex(p1), _pkt_hex(p2)]
        result = _run(pc.save_pcap(hexes, filename="test_save.pcap"))
        assert "Saved 2 packet(s)" in result
        assert "test_save.pcap" in result
        pcap_path = tmp_path / "test_save.pcap"
        assert pcap_path.exists()
        # sha256 in result matches the file
        file_bytes = pcap_path.read_bytes()
        assert hashlib.sha256(file_bytes).hexdigest() in result
        # Round-trip: read it back with scapy
        pkts = scapy.rdpcap(str(pcap_path))
        assert len(pkts) == 2

    def test_save_auto_filename(self, tmp_path, monkeypatch):
        """save_pcap auto-generates a timestamped name when filename is omitted."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        hexes = [_pkt_hex(_make_tcp_pkt())]
        result = _run(pc.save_pcap(hexes))
        assert "Saved 1 packet(s)" in result
        # Should have a cap_YYYYMMDD_HHMMSS.pcap name
        assert "cap_" in result
        pcaps = list(tmp_path.glob("cap_*.pcap"))
        assert len(pcaps) == 1

    def test_save_empty_list(self, tmp_path, monkeypatch):
        """save_pcap with an empty hex list returns a clear message."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        result = _run(pc.save_pcap([], filename="empty.pcap"))
        assert "no packets to save" in result.lower()
        assert not (tmp_path / "empty.pcap").exists()

    def test_save_strips_path_separators(self, tmp_path, monkeypatch):
        """save_pcap strips path separators from filename — file always lands in PCAP_DIR."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        hexes = [_pkt_hex(_make_tcp_pkt())]
        # Attempt to write to a subdirectory — should be stripped to basename
        result = _run(pc.save_pcap(hexes, filename="../../evil.pcap"))
        assert "evil.pcap" in result
        assert (tmp_path / "evil.pcap").exists()
        # No directory traversal
        assert not (tmp_path.parent.parent / "evil.pcap").exists()

    def test_save_appends_pcap_extension(self, tmp_path, monkeypatch):
        """save_pcap adds .pcap extension if missing."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        hexes = [_pkt_hex(_make_tcp_pkt())]
        result = _run(pc.save_pcap(hexes, filename="noext"))
        assert "noext.pcap" in result
        assert (tmp_path / "noext.pcap").exists()


# --- load_pcap -------------------------------------------------------------

class TestLoadPcap:
    def test_load_all_packets(self, tmp_path, monkeypatch):
        """load_pcap returns all packets from a multi-packet pcap."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        p1 = _make_tcp_pkt()
        p2 = scapy.IP(src="10.0.0.3", dst="10.0.0.4") / scapy.TCP(sport=80, dport=1234, flags="A")
        scapy.wrpcap(str(tmp_path / "multi.pcap"), [p1, p2])
        result = _run(pc.load_pcap("multi.pcap"))
        assert "2 packet(s)" in result
        assert "10.0.0.1" in result or "10.0.0.3" in result
        # hex present for dissection
        assert "hex=" in result

    def test_load_pagination(self, tmp_path, monkeypatch):
        """load_pcap respects offset/limit for paging through large captures."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        pkts = []
        for i in range(10):
            pkts.append(scapy.IP(src=f"10.0.0.{i+1}", dst="10.0.0.99") / scapy.TCP(sport=i+1, dport=80, flags="S"))
        scapy.wrpcap(str(tmp_path / "page.pcap"), pkts)
        # Page 1: offset=0, limit=3
        page1 = _run(pc.load_pcap("page.pcap", offset=0, limit=3))
        assert "showing 0–2 of 10" in page1
        assert "7 more" in page1
        # Page 2: offset=3, limit=3
        page2 = _run(pc.load_pcap("page.pcap", offset=3, limit=3))
        assert "showing 3–5 of 10" in page2
        # Last page: offset=9, limit=3
        last = _run(pc.load_pcap("page.pcap", offset=9, limit=3))
        assert "showing 9–9 of 10" in last
        assert "End of capture" in last

    def test_load_bare_name_resolves_to_pcap_dir(self, tmp_path, monkeypatch):
        """A bare filename (no path separators) resolves against PCAP_DIR."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        scapy.wrpcap(str(tmp_path / "named.pcap"), [_make_tcp_pkt()])
        result = _run(pc.load_pcap("named.pcap"))
        assert "1 packet(s)" in result

    def test_load_absolute_path_used_as_is(self, tmp_path, monkeypatch):
        """An absolute path is used directly, not resolved against PCAP_DIR."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        abs_path = tmp_path / "abs.pcap"
        scapy.wrpcap(str(abs_path), [_make_tcp_pkt()])
        result = _run(pc.load_pcap(str(abs_path)))
        assert "1 packet(s)" in result

    def test_load_nonexistent_file(self, tmp_path, monkeypatch):
        """load_pcap on a missing file returns a clear not-found message."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        result = _run(pc.load_pcap("nonexistent.pcap"))
        assert "not found" in result.lower()

    def test_load_empty_pcap(self, tmp_path, monkeypatch):
        """load_pcap on a valid but empty pcap reports zero packets."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        # Create an empty pcap (valid header, no packets)
        scapy.wrpcap(str(tmp_path / "empty.pcap"), [])
        result = _run(pc.load_pcap("empty.pcap"))
        # scapy may report 0 packets or the file may be too small
        assert "0 packet" in result or "No packets" in result or "not found" in result.lower()

    def test_load_size_guard(self, tmp_path, monkeypatch):
        """load_pcap refuses files exceeding PCAP_MAX_FILE_MB."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        # Write a small pcap but set the cap to 0 MiB
        scapy.wrpcap(str(tmp_path / "tiny.pcap"), [_make_tcp_pkt()])
        monkeypatch.setattr(pc, "_pcap_max_file_mb", lambda: 0)
        result = _run(pc.load_pcap("tiny.pcap"))
        assert "exceeds" in result.lower() or "cap is" in result.lower() or "MiB" in result


# --- list_pcaps ------------------------------------------------------------

class TestListPcaps:
    def test_list_shows_pcap_files(self, tmp_path, monkeypatch):
        """list_pcaps shows pcap files with metadata."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        scapy.wrpcap(str(tmp_path / "a.pcap"), [_make_tcp_pkt()])
        p2 = scapy.IP(src="10.0.0.3", dst="10.0.0.4") / scapy.TCP(sport=80, dport=1234, flags="A")
        scapy.wrpcap(str(tmp_path / "b.pcap"), [_make_tcp_pkt(), p2])
        result = _run(pc.list_pcaps())
        assert "2 file(s)" in result
        assert "a.pcap" in result
        assert "b.pcap" in result
        # Packet counts shown
        assert "1 pkts" in result
        assert "2 pkts" in result

    def test_list_filters_non_pcap_files(self, tmp_path, monkeypatch):
        """list_pcaps filters out .gitkeep, README.md, etc."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        (tmp_path / ".gitkeep").write_text("")
        (tmp_path / "README.md").write_text("meta")
        scapy.wrpcap(str(tmp_path / "real.pcap"), [_make_tcp_pkt()])
        result = _run(pc.list_pcaps())
        assert "1 file(s)" in result
        assert "real.pcap" in result
        assert "README.md" not in result
        assert ".gitkeep" not in result

    def test_list_empty_dir(self, tmp_path, monkeypatch):
        """list_pcaps on an empty dir returns a helpful message."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        (tmp_path / ".gitkeep").write_text("")
        result = _run(pc.list_pcaps())
        assert "No pcap files" in result
        assert "sniff_to_pcap" in result or "save_pcap" in result


# --- sniff_to_pcap (stubbed — no raw sockets needed) -----------------------

class TestSniffToPcap:
    def test_sniff_to_pcap_saves_capture(self, tmp_path, monkeypatch):
        """sniff_to_pcap sniffs (stubbed) and saves the capture to a pcap."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        canned_pkts = [_make_tcp_pkt()]
        # Stub the PacketCraft.sniff_packets method to return canned packets
        real_craft = pc._craft
        class StubCraft:
            interface = "lo"
            def sniff_packets(self, filter="", count=10, timeout=30):
                return canned_pkts
        monkeypatch.setattr(pc, "_craft", lambda iface="": StubCraft())
        try:
            result = _run(pc.sniff_to_pcap(filter="tcp port 80", count=1, timeout=5, interface="lo"))
        finally:
            pass
        assert "Captured and saved 1 packet(s)" in result
        assert ".pcap" in result
        # Verify the file was actually written
        pcaps = list(tmp_path.glob("cap_*.pcap"))
        assert len(pcaps) == 1
        pkts = scapy.rdpcap(str(pcaps[0]))
        assert len(pkts) == 1

    def test_sniff_to_pcap_no_packets(self, tmp_path, monkeypatch):
        """sniff_to_pcap with no captured packets returns a clear message and writes no file."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        class StubCraft:
            interface = "lo"
            def sniff_packets(self, filter="", count=10, timeout=30):
                return []
        monkeypatch.setattr(pc, "_craft", lambda iface="": StubCraft())
        result = _run(pc.sniff_to_pcap(filter="tcp", count=1, timeout=1, interface="lo"))
        assert "No packets captured" in result
        assert "No pcap file written" in result
        assert not list(tmp_path.glob("*.pcap"))

    def test_sniff_to_pcap_custom_filename(self, tmp_path, monkeypatch):
        """sniff_to_pcap respects a custom filename."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        canned_pkts = [_make_tcp_pkt()]
        class StubCraft:
            interface = "lo"
            def sniff_packets(self, filter="", count=10, timeout=30):
                return canned_pkts
        monkeypatch.setattr(pc, "_craft", lambda iface="": StubCraft())
        result = _run(pc.sniff_to_pcap(filename="my_capture.pcap", interface="lo"))
        assert "my_capture.pcap" in result
        assert (tmp_path / "my_capture.pcap").exists()


# --- round-trip integration ------------------------------------------------

class TestRoundTrip:
    def test_save_then_load_round_trip(self, tmp_path, monkeypatch):
        """save_pcap -> load_pcap round-trips packets faithfully."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        p1 = _make_tcp_pkt()
        p2 = scapy.IP(src="10.0.0.3", dst="10.0.0.4") / scapy.UDP(sport=53, dport=53) / scapy.DNS(qd=scapy.DNSQR(qname="example.com"))
        hexes = [_pkt_hex(p1), _pkt_hex(p2)]
        save_result = _run(pc.save_pcap(hexes, filename="roundtrip.pcap"))
        assert "Saved 2 packet(s)" in save_result
        load_result = _run(pc.load_pcap("roundtrip.pcap"))
        assert "2 packet(s)" in load_result
        # Verify the loaded hexes round-trip back to valid packets
        # Extract hex values from the load result
        import re
        hex_matches = re.findall(r'hex=([0-9a-f]+)', load_result)
        assert len(hex_matches) == 2
        rt1 = pc._packet_from_hex(hex_matches[0])
        rt2 = pc._packet_from_hex(hex_matches[1])
        assert rt1.haslayer(scapy.TCP)
        assert rt2.haslayer(scapy.UDP)
        assert rt2.haslayer(scapy.DNS)

    def test_full_workflow_save_list_load(self, tmp_path, monkeypatch):
        """save_pcap -> list_pcaps -> load_pcap workflow."""
        monkeypatch.setattr(pc, "_pcap_dir", lambda: tmp_path)
        hexes = [_pkt_hex(_make_tcp_pkt())]
        # Save
        save_result = _run(pc.save_pcap(hexes, filename="workflow.pcap"))
        assert "Saved" in save_result
        # List
        list_result = _run(pc.list_pcaps())
        assert "workflow.pcap" in list_result
        assert "1 pkts" in list_result
        # Load
        load_result = _run(pc.load_pcap("workflow.pcap"))
        assert "1 packet(s)" in load_result
        assert "hex=" in load_result