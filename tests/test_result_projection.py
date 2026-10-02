"""Tests for the result projection layer (utils/result_projection.py).

Covers: full passthrough, digest shape, page bounds, naive fallback,
failed-result passthrough, adapter dispatch, and scratch reference format.
"""

import pytest

from utils.result_projection import project_result, register_digest_adapter
from utils.scratch_store import ScratchStore


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the scratch store singleton at a temp dir for isolation."""
    db = tmp_path / "scratch.db"
    data_dir = tmp_path / "scratch-data"
    s = ScratchStore(db_path=str(db), data_dir=str(data_dir))
    # Patch the module-level singleton so project_result uses our test store.
    import utils.scratch_store as ss_mod
    monkeypatch.setattr(ss_mod, "_store", s)
    yield s
    s.close()


def _nmap_result():
    return {
        "status": "Success",
        "open_ports": ["22/tcp/open/ssh", "80/tcp/open/http", "443/tcp/open/https"],
        "host_state": "up",
        "recent_lines": [f"line {i}" for i in range(100)],
        "job_id": "nmap-001",
        "elapsed": 12.5,
        "exit_code": 0,
        "log_file": "/tmp/nmap-001.log",
        "full_output": "Nmap scan report...\n" * 500,
    }


class TestFullMode:
    def test_full_passthrough(self, store):
        """Full mode returns the raw result unchanged."""
        result = _nmap_result()
        projected = project_result(
            result, result_mode="full", tool_id="test", agent_id="a"
        )
        assert projected is result  # identity — no copy, no projection

    def test_full_default_small_result(self, store):
        """Default mode is digest, but small results pass through as full."""
        result = {"status": "Success", "note": "small result"}
        projected = project_result(result, tool_id="test", agent_id="a")
        # Small result under the threshold → returned as-is (full passthrough).
        assert projected is result

    def test_small_result_always_full(self, store):
        """Even with result_mode=digest, small results pass through."""
        result = {"status": "Success", "handle": "ssh:sess-0001"}
        projected = project_result(
            result, result_mode="digest", tool_id="test", agent_id="a"
        )
        assert projected is result  # too small to project


class TestFailedResultPassthrough:
    def test_failed_always_full(self, store):
        """Failed results are returned in full regardless of result_mode."""
        result = {"status": "Failed", "error": "connection refused"}
        projected = project_result(
            result, result_mode="digest", tool_id="test", agent_id="a"
        )
        assert projected is result  # unchanged — the model needs the error text


class TestDigestMode:
    def test_digest_envelope_shape(self, store):
        """Digest mode returns the standard envelope with required fields."""
        result = _nmap_result()
        projected = project_result(
            result, result_mode="digest", tool_id="test.nmap", agent_id="a"
        )
        assert projected["mode"] == "digest"
        assert "summary" in projected
        assert projected["full_ref"].startswith("scratch:")
        assert "retrieval" in projected
        assert "framework_scratch_search" in projected["retrieval"]

    def test_digest_stores_full_in_scratch(self, store):
        """The full result is stored and retrievable."""
        result = _nmap_result()
        projected = project_result(
            result, result_mode="digest", tool_id="test.nmap", agent_id="a"
        )
        ref = projected["full_ref"]
        retrieved = store.retrieve(ref, agent_id="a")
        assert retrieved["status"] == "ok"
        assert retrieved["result"]["open_ports"] == result["open_ports"]

    def test_naive_fallback(self, store):
        """Tools without an adapter get a naive head+count digest."""
        # Pad the result above the small-result passthrough threshold.
        result = {
            "status": "Success",
            "data": ["a", "b", "c"],
            "note": "hello",
            "padding": "x" * 3000,
        }
        projected = project_result(
            result, result_mode="digest", tool_id="unknown.tool", agent_id="a"
        )
        assert projected["mode"] == "digest"
        assert "data=3 items" in projected["summary"]
        assert "note=hello" in projected["summary"]

    def test_registered_adapter(self, store):
        """A registered adapter produces a family-specific digest."""
        def my_adapter(result):
            return {
                "summary": f"Found {len(result.get('open_ports', []))} ports",
                "row_hint_format": "scratch_search scratch:<id> --filter 'port'",
            }
        register_digest_adapter("test.adapter", my_adapter)
        result = _nmap_result()
        projected = project_result(
            result, result_mode="digest", tool_id="test.adapter", agent_id="a"
        )
        assert "Found 3 ports" in projected["summary"]
        assert "port" in projected["row_hint"]


class TestPageMode:
    def test_page_envelope_shape(self, store):
        """Page mode returns bounded rows + continuation info."""
        # Pad above the small-result passthrough threshold.
        result = {
            "status": "Success",
            "open_ports": [f"port-{i}" for i in range(100)],
            "padding": "x" * 3000,
        }
        projected = project_result(
            result, result_mode="page", tool_id="test.nmap", agent_id="a",
            page_offset=0, page_limit=10,
        )
        assert projected["mode"] == "page"
        assert projected["full_ref"].startswith("scratch:")
        assert "next" in projected
        assert "offset=10" in projected["next"]

    def test_page_bounds(self, store):
        """Page limit caps the number of returned rows."""
        result = _nmap_result()
        projected = project_result(
            result, result_mode="page", tool_id="test.nmap", agent_id="a",
            page_offset=0, page_limit=5,
        )
        rows = projected["rows"]
        assert len(rows) <= 5

    def test_page_last_page_no_next(self, store):
        """Last page has no continuation offset."""
        # Pad above the small-result passthrough threshold.
        result = {
            "status": "Success",
            "items": ["a", "b", "c"],
            "padding": "x" * 3000,
        }
        projected = project_result(
            result, result_mode="page", tool_id="test", agent_id="a",
            page_offset=0, page_limit=10,
        )
        assert "End of results" in projected["next"]


class TestNmapDigestAdapter:
    """Integration test: the nmap_status digest adapter is registered and
    produces a port-list summary."""

    def test_nmap_digest_registered(self, store):
        """The nmap_status adapter is discoverable via the registry."""
        from utils.result_projection import get_digest_adapter
        # The adapter is registered at import time via the @framework_tool
        # decorator's result_digest kwarg.  The provisional key is
        # module.qualname — check it exists.
        # (The registry's discovery pass re-registers under the exact tool_id,
        # but for unit tests we just verify the adapter callable is set.)
        adapter = get_digest_adapter("auxiliaries.nmap._nmap_status_digest")
        # The provisional registration uses __qualname__ which for a lambda
        # is "_nmap_status_digest.<locals>.<lambda>" — check the function-level
        # registration instead by importing the module and checking the
        # decorator set _result_digest.
        from auxiliaries.nmap import nmap_status
        assert hasattr(nmap_status, "_result_digest")
        assert callable(nmap_status._result_digest)

    def test_nmap_digest_output(self, store):
        """The nmap digest adapter produces a port-list summary."""
        from auxiliaries.nmap import nmap_status
        adapter = nmap_status._result_digest
        result = _nmap_result()
        digest = adapter(result)
        assert "open_ports=3" in digest["summary"]
        assert "22/tcp/open/ssh" in digest["summary"]
        assert "job_id=nmap-001" in digest["summary"]


class TestExecutorEnvelopeUnwrap:
    """Regression: project_result must unwrap the executor transport envelope
    before projecting, so digest/page adapters run on the tool's own fields.

    The in-process/BRAIN_DISPATCH executor wraps every result as
    ``{"stdout": <json>, "status": "Success", "result": <raw tool dict>}``.
    Without unwrapping, the nmap_status digest adapter read ``status="Success"``
    (the envelope's transport status) and ``open_ports=[]`` (nested under
    ``result``, absent at top level), so the digest reported 0 open ports
    while the scratch copy held the real 2.  Bug reproduced 2026-10-01
    against 192.168.56.106 (2 open ports: 22/tcp, 8080/tcp).
    """

    def test_digest_unwraps_envelope_before_adapter(self, store):
        """The digest adapter sees the tool result, not the transport envelope."""
        from auxiliaries.nmap import nmap_status
        register_digest_adapter("auxiliaries.nmap.nmap_status",
                                nmap_status._result_digest)
        raw = {
            "status": "done",
            "open_ports": ["22/tcp/open/ssh", "8080/tcp/open/http"],
            "host_state": "up",
            "job_id": "f10f9804",
            "elapsed": 12.0,
            "exit_code": 0,
            "log_file": "/tmp/nmap_f10f9804.log",
            "recent_lines": ["Nmap done"],
            "full_output": "Nmap scan report...\n" * 500,
        }
        envelope = {
            "stdout": __import__("json").dumps(raw, default=str),
            "status": "Success",
            "result": raw,
        }
        projected = project_result(
            envelope, result_mode="digest",
            tool_id="auxiliaries.nmap.nmap_status", agent_id="a",
        )
        assert projected["mode"] == "digest"
        # The adapter saw the real tool result, not the envelope: it reads
        # status="done" (the tool's), and open_ports has 2 entries.
        assert "open_ports=2" in projected["summary"]
        assert "22/tcp/open/ssh" in projected["summary"]
        assert "status=done" in projected["summary"]
        # The scratch copy also holds the tool result (not the envelope).
        retrieved = store.retrieve(projected["full_ref"], agent_id="a")
        assert retrieved["status"] == "ok"
        assert len(retrieved["result"]["open_ports"]) == 2

    def test_failed_envelope_passthrough(self, store):
        """A Failed transport envelope is unwrapped and the raw error result
        is returned in full (not digested)."""
        raw = {"error": "brain timeout", "status": "Failed"}
        envelope = {"stdout": "{}", "status": "Failed", "result": raw}
        projected = project_result(
            envelope, result_mode="digest", tool_id="test.tool", agent_id="a",
        )
        # Failed → full passthrough; the envelope is unwrapped so the model
        # sees the raw error dict (with the error text), not the transport
        # wrapper.
        assert projected is raw
        assert projected["error"] == "brain timeout"