"""Offline tests for REPL ↔ Brain shared-session plumbing.

No live targets and no live Brain: the sidecar is faked with a tiny asyncio
UDS server speaking the same 4-byte length-prefixed CALL_TOOL wire protocol
as listeners/thebrain.py.
"""

import asyncio
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The harness import chain (tool_repl -> daharness) triggers a module-level
# ``load_dotenv()``; on a root-0600 ``.env`` that PermissionErrors for a
# non-root caller. Stub dotenv before the import — same pattern as
# tests/test_scope_gate.py's metasploiting loader. Skipped when dotenv is
# already imported cleanly (readable .env).
import types as _types

if "dotenv" not in sys.modules:
    _dotenv_stub = _types.ModuleType("dotenv")
    _dotenv_stub.load_dotenv = lambda *a, **k: None
    _dotenv_stub.dotenv_values = lambda *a, **k: {}
    sys.modules["dotenv"] = _dotenv_stub

import tool_repl as tr


class TestBrainFraming:
    def test_pack_matches_thebrain_wire_format(self):
        """Byte-identical framing to listeners/thebrain.pack_message: 4-byte
        big-endian length prefix + payload."""
        payload = b"CALL_TOOL|0|utils.paramiko_client.list_sessions|{}"
        wire = tr._brain_pack(payload)
        (length,) = struct.unpack("!I", wire[:4])
        assert length == len(payload)
        assert wire[4:] == payload


class TestBrainCall:
    def test_roundtrip_against_fake_brain(self, tmp_path, monkeypatch):
        sock_path = str(tmp_path / "brain.sock")
        seen = {}

        async def fake_brain(reader, writer):
            header = await reader.readexactly(4)
            (n,) = struct.unpack("!I", header)
            seen["message"] = (await reader.readexactly(n)).decode()
            reply = json.dumps(
                {
                    "status": "success",
                    "tool_id": "utils.paramiko_client.list_sessions",
                    "result": "SSH sessions:\n  (none)",
                }
            )
            writer.write(tr._brain_pack(reply.encode()))
            await writer.drain()
            writer.close()

        monkeypatch.setattr(tr, "BRAIN_SOCKET", sock_path)

        async def main():
            server = await asyncio.start_unix_server(fake_brain, path=sock_path)
            async with server:
                return await tr._brain_call(
                    "utils.paramiko_client.list_sessions", {}
                )

        res = asyncio.run(main())

        assert (
            seen["message"] == "CALL_TOOL|0|utils.paramiko_client.list_sessions|{}"
        )
        assert res["status"] == "Success"
        assert "SSH sessions" in res["stdout"]
        assert "_elapsed_s" in res

    def test_brain_down_refuses_in_process(self, tmp_path, monkeypatch):
        """No in-process fallback on Brain-down: the refusal is the feature
        (a fallback would strand the session REPL-local, invisible to the
        agent — the split-brain this helper exists to prevent)."""
        monkeypatch.setattr(tr, "BRAIN_SOCKET", str(tmp_path / "absent.sock"))
        res = asyncio.run(
            tr._brain_call(
                "utils.paramiko_client.ssh_connect",
                {"hostname": "127.0.0.1", "username": "u", "password": "p"},
            )
        )
        assert res["status"] == "Failed"
        assert "Refusing to run" in res["error"]

    def test_error_envelope_mapping(self, tmp_path, monkeypatch):
        sock_path = str(tmp_path / "brain.sock")

        async def fake_brain(reader, writer):
            header = await reader.readexactly(4)
            (n,) = struct.unpack("!I", header)
            await reader.readexactly(n)
            reply = json.dumps(
                {
                    "status": "error",
                    "tool_id": "t",
                    "error": "Tool t not found in registry.",
                }
            )
            writer.write(tr._brain_pack(reply.encode()))
            await writer.drain()
            writer.close()

        monkeypatch.setattr(tr, "BRAIN_SOCKET", sock_path)

        async def main():
            server = await asyncio.start_unix_server(fake_brain, path=sock_path)
            async with server:
                return await tr._brain_call("t", {})

        res = asyncio.run(main())
        assert res["status"] == "Failed"
        assert "not found in registry" in res["error"]


class TestBrainScansSessionSidecar:
    """The Brain must register utils.paramiko_client at startup or ssh:
    sessions strand in whichever process hit the in-process fallback — the
    exact cross-lane gap the shared-session feature closes. Checked as a
    read-only source assertion so the test never imports the Brain module
    (its ctypes CDLL load is a side effect unit tests must not carry)."""

    def test_startup_scan_registers_paramiko_sidecar(self):
        src = (
            Path(__file__).resolve().parent.parent / "listeners" / "thebrain.py"
        ).read_text()
        assert "utils.paramiko_client" in src
        assert "registry.scan_module(_paramiko_sidecar)" in src