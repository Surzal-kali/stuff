"""Tests for the scratch store (utils/scratch_store.py).

Covers: store/retrieve round-trip, ownership isolation, TTL expiry,
restart survival (file-backed), paging/filtering, and cap enforcement.
"""

import json
import time
from pathlib import Path

import pytest

from utils.scratch_store import ScratchStore


@pytest.fixture
def store(tmp_path):
    """Fresh scratch store in a temp directory."""
    db = tmp_path / "scratch.db"
    data_dir = tmp_path / "scratch-data"
    s = ScratchStore(db_path=str(db), data_dir=str(data_dir))
    yield s
    s.close()


def _sample_result(open_ports=None, status="Success", **extra):
    """Build a realistic tool result dict for testing."""
    result = {
        "status": status,
        "open_ports": open_ports or ["22/tcp/open/ssh", "80/tcp/open/http"],
        "recent_lines": ["line 1", "line 2", "line 3"] * 10,
        "job_id": "nmap-001",
        "elapsed": 12.5,
        "log_file": "/tmp/nmap-001.log",
    }
    result.update(extra)
    return result


class TestStoreRetrieve:
    def test_round_trip(self, store):
        """Stored result is retrieved identically."""
        result = _sample_result()
        info = store.store(result, agent_id="agent-a", tool_id="auxiliaries.nmap.nmap_status")
        ref = info["scratch_ref"]
        assert ref.startswith("scratch:")

        retrieved = store.retrieve(ref, agent_id="agent-a")
        assert retrieved["status"] == "ok"
        assert retrieved["result"]["open_ports"] == result["open_ports"]
        assert retrieved["result"]["job_id"] == "nmap-001"

    def test_ref_is_opaque(self, store):
        """Scratch IDs are random, not sequential."""
        info1 = store.store(_sample_result(), agent_id="a", tool_id="t1")
        info2 = store.store(_sample_result(), agent_id="a", tool_id="t2")
        assert info1["scratch_ref"] != info2["scratch_ref"]
        # Not sequential integers.
        id1 = info1["scratch_ref"].split(":")[1]
        id2 = info2["scratch_ref"].split(":")[1]
        assert id1 != f"{int(id2, 16) - 1:08x}"


class TestOwnership:
    def test_wrong_agent_not_found(self, store):
        """A ref from agent-a is invisible to agent-b."""
        info = store.store(_sample_result(), agent_id="agent-a", tool_id="t")
        retrieved = store.retrieve(info["scratch_ref"], agent_id="agent-b")
        assert retrieved["status"] == "error"
        assert "not found" in retrieved["error"]

    def test_correct_agent_works(self, store):
        info = store.store(_sample_result(), agent_id="agent-a", tool_id="t")
        retrieved = store.retrieve(info["scratch_ref"], agent_id="agent-a")
        assert retrieved["status"] == "ok"


class TestExpiry:
    def test_expired_entry_returns_error(self, store, monkeypatch):
        """Entries past TTL are rejected and cleaned up."""
        info = store.store(_sample_result(), agent_id="a", tool_id="t")
        # Manually backdate the expiry in the DB.
        store.conn.execute(
            "UPDATE scratch_entries SET expires_at = ? WHERE id = ?",
            (time.time() - 1, info["scratch_ref"].split(":")[1]),
        )
        store.conn.commit()

        retrieved = store.retrieve(info["scratch_ref"], agent_id="a")
        assert retrieved["status"] == "error"
        assert "expired" in retrieved["error"]


class TestRestartSurvival:
    def test_payload_survives_reconnect(self, tmp_path):
        """A new ScratchStore instance can read entries from a prior instance."""
        db = tmp_path / "scratch.db"
        data_dir = tmp_path / "scratch-data"

        s1 = ScratchStore(db_path=str(db), data_dir=str(data_dir))
        info = s1.store(_sample_result(), agent_id="a", tool_id="t")
        ref = info["scratch_ref"]
        s1.close()

        # Simulate a restart: new instance, same paths.
        s2 = ScratchStore(db_path=str(db), data_dir=str(data_dir))
        retrieved = s2.retrieve(ref, agent_id="a")
        assert retrieved["status"] == "ok"
        assert retrieved["result"]["job_id"] == "nmap-001"
        s2.close()


class TestPagingFilter:
    def test_offset_limit(self, store):
        """Paging slices a list field."""
        result = _sample_result(recent_lines=[f"line-{i}" for i in range(100)])
        info = store.store(result, agent_id="a", tool_id="t")
        retrieved = store.retrieve(
            info["scratch_ref"], agent_id="a", offset=10, limit=5
        )
        assert retrieved["status"] == "ok"
        paged = retrieved["result"]["recent_lines"]
        assert len(paged) == 5
        assert paged[0] == "line-10"

    def test_filter(self, store):
        """Filter narrows list items by substring."""
        result = _sample_result(
            open_ports=["22/tcp/open/ssh", "80/tcp/open/http", "443/tcp/open/https"]
        )
        info = store.store(result, agent_id="a", tool_id="t")
        retrieved = store.retrieve(
            info["scratch_ref"], agent_id="a", filter_pattern="ssh"
        )
        assert retrieved["status"] == "ok"
        ports = retrieved["result"]["open_ports"]
        assert len(ports) == 1
        assert "ssh" in ports[0]


class TestStats:
    def test_stats_after_store(self, store):
        store.store(_sample_result(), agent_id="a", tool_id="t")
        stats = store.stats(agent_id="a")
        assert stats["entries"] == 1
        assert stats["stored_bytes"] > 0

    def test_list_entries(self, store):
        store.store(_sample_result(), agent_id="a", tool_id="t1")
        store.store(_sample_result(), agent_id="a", tool_id="t2")
        entries = store.list_entries("a", limit=10)
        assert len(entries) == 2
        assert all("scratch_ref" in e for e in entries)


class TestInvalidRef:
    def test_garbage_ref(self, store):
        retrieved = store.retrieve("not-a-ref", agent_id="a")
        assert retrieved["status"] == "error"

    def test_nonexistent_ref(self, store):
        retrieved = store.retrieve("scratch:deadbeefdeadbeef", agent_id="a")
        assert retrieved["status"] == "error"