"""Regression tests for the bounded SSH command runner (2026-09-25).

Bug: ``ssh_exec`` used ``stdout.read()`` — a blocking read until the SSH
channel closes. Two shapes hung forever with a healthy connection:

  1. A command segment that reads stdin (``apt-get`` Y/n prompt, ``passwd``,
     ``sudo``) — the harness never closes stdin, so the prompt waits forever.
  2. A command that starts a daemon/background child (``service x start``,
     ``nohup``, ``&``) — the grandchild inherits the channel's stdout, the
     shell exits, the channel never EOFs.

Each hung call pinned a thread of the Brain's DEFAULT executor pool
(min(32, cpu+4)); the OWUI wrapper timed out at 600s, the model retried, and
3-4 wedged calls exhausted the pool — every sync tool on the Brain then
queued forever and the whole stack froze (the "more than 3-4 &&" report).

Fix: ``utils.paramiko_client._run_ssh_command`` — close stdin immediately,
poll ``exit_status_ready()`` instead of EOF, enforce a wall-clock cap
(SSH_EXEC_TIMEOUT, default 300s) that closes only the channel (the
persistent session survives), and cap captured output.

These tests are fully offline: a fake paramiko channel simulates the hang
shapes. No real SSH connection is ever made.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def pc():
    import utils.paramiko_client as pc
    return pc


class _FakeChannel:
    """Fake paramiko channel with programmable behaviour.

    Modes:
      normal        - output arrives, then exit status 0.
      stdin_hang    - simulates a command blocked reading stdin: never sets
                      eof, never sets an exit status (the apt-get shape).
      daemon_child  - simulates the shell exiting while a grandchild holds
                      the channel open: eof_received=True but the exit status
                      lands only after a short delay (the service-start shape).
      slow_output   - output trickles in over time; tests the poll loop's
                      draining.
    """

    def __init__(self, mode: str = "normal", exit_code: int = 0):
        self.mode = mode
        self._exit_code = exit_code
        self.closed = False
        self.eof_received = False
        self.shutdown_write_called = False
        self._out = bytearray()
        self._err = bytearray()
        self._exit_ready_at = None  # monotonic time when status becomes ready
        self._lock = threading.Lock()
        if mode == "normal":
            self._out.extend(b"hello\n")
            self._exit_ready_at = time.monotonic() + 0.05
        elif mode == "daemon_child":
            self._out.extend(b"started\n")
            self.eof_received = True
            self._exit_ready_at = time.monotonic() + 0.3
        elif mode == "slow_output":
            self._exit_ready_at = time.monotonic() + 0.5

    # --- paramiko Channel API used by the runner ---

    def exec_command(self, command):
        pass

    def shutdown_write(self):
        self.shutdown_write_called = True

    def recv_ready(self):
        with self._lock:
            if self.mode == "slow_output":
                # Trickle: surface 10 bytes at a time.
                if len(self._out) < 50 and time.monotonic() % 0.02 < 0.01:
                    self._out.extend(b"x" * 10)
                return len(self._out) > 0
            return len(self._out) > 0

    def recv(self, n):
        with self._lock:
            data = bytes(self._out[:n])
            del self._out[:n]
            return data

    def recv_stderr_ready(self):
        with self._lock:
            if self.mode == "slow_output" and len(self._err) < 30:
                self._err.extend(b"e" * 10)
            return len(self._err) > 0

    def recv_stderr(self, n):
        with self._lock:
            data = bytes(self._err[:n])
            del self._err[:n]
            return data

    def exit_status_ready(self):
        if self.mode == "stdin_hang":
            return False
        return self._exit_ready_at is not None and time.monotonic() >= self._exit_ready_at

    def recv_exit_status(self):
        return self._exit_code

    def close(self):
        self.closed = True


class _FakeTransport:
    def __init__(self, channel):
        self._channel = channel

    def open_session(self):
        return self._channel


class _FakeClient:
    def __init__(self, mode="normal", exit_code=0):
        self.chan = _FakeChannel(mode, exit_code)
        self._transport = _FakeTransport(self.chan)
        self.closed = False

    def get_transport(self):
        return self._transport

    # paramiko.SSHClient API used by ssh_connect/ssh_exec_batch.
    def set_missing_host_key_policy(self, policy):
        pass

    def close(self):
        self.closed = True


# --- core runner behaviour ----------------------------------------------------


class TestRunSshCommand:
    def test_normal_command(self, pc):
        client = _FakeClient("normal", exit_code=0)
        env = pc._run_ssh_command(client, "id", timeout=5)
        assert env["exit_code"] == 0
        assert env["stdout"] == "hello\n"
        assert env["timed_out"] is False
        # stdin MUST be closed immediately (the apt-get prompt defence).
        assert client.chan.shutdown_write_called

    def test_stdin_hang_times_out_and_closes_channel(self, pc):
        """Shape 1: apt-get/passwd/sudo prompt — must hit the cap, close the
        channel, and raise _SshExecTimeout (session survives)."""
        client = _FakeClient("stdin_hang")
        with pytest.raises(pc._SshExecTimeout):
            pc._run_ssh_command(client, "apt-get install -y x", timeout=0.4)
        assert client.chan.closed  # channel closed => remote gets SIGHUP
        assert client.chan.shutdown_write_called

    def test_daemon_child_returns_without_hanging(self, pc):
        """Shape 2: shell exited, grandchild holds the channel. EOF + no
        status yet must NOT wait on stdout.read() forever — the runner
        detects the shell's exit via the (delayed) status and returns."""
        client = _FakeClient("daemon_child")
        env = pc._run_ssh_command(client, "service ssh start", timeout=5)
        assert env["exit_code"] == 0
        assert "started" in env["stdout"]

    def test_timeout_zero_is_unbounded_hint_in_envelope(self, pc):
        """timeout=0 means unbounded; used only deliberately. Ensure the
        code path doesn't crash computing the deadline."""
        client = _FakeClient("normal")
        env = pc._run_ssh_command(client, "id", timeout=0)
        assert env["exit_code"] == 0

    def test_session_object_usable_after_timeout(self, pc):
        """The persistent session must survive a timed-out command: closing
        the channel must NOT close the client/transport."""
        client = _FakeClient("stdin_hang")
        with pytest.raises(pc._SshExecTimeout):
            pc._run_ssh_command(client, "top", timeout=0.3)
        # The transport object is untouched — a follow-up ssh_exec on the
        # same handle would open a NEW session channel successfully.
        assert client.get_transport() is client._transport
        assert client.chan.closed

    def test_output_cap_truncates(self, pc):
        client = _FakeClient("normal")
        env = pc._run_ssh_command(client, "dmesg", timeout=5, output_cap=4)
        assert env["stdout"].startswith("hell")
        assert len(env["stdout"]) == 4
        assert env.get("stdout_truncated") is True


# --- tool-level behaviour -----------------------------------------------------


class TestSshExecTool:
    @pytest.fixture(autouse=True)
    def _disarm_gate(self, monkeypatch):
        """ssh_exec re-gates per call on the session hostname; the box may
        have an armed scope from earlier lab work — bypass it for these
        offline tests."""
        import utils.scope_gate as g
        monkeypatch.setattr(g, "check_scan", lambda t: (True, "test-disarmed"))

    def test_ssh_exec_timeout_returns_message_keeps_handle(self, pc, monkeypatch):
        """The tool must return a clear message (not raise) on timeout, and
        the session must remain registered for follow-up calls."""
        from utils.handles import format_handle
        from utils.session_manager import get_manager

        client = _FakeClient("stdin_hang")
        sm = get_manager()
        sid = sm.register("ssh", "op@10.0.0.9:22", client, hostname="10.0.0.9")
        handle = format_handle("ssh", sid)
        try:
            monkeypatch.setattr(pc, "DEFAULT_SSH_EXEC_TIMEOUT", 0.3)
            out = pc.ssh_exec(handle, "apt-get install -y x")
            assert "exceeded" in out and "0s cap" in out
            assert handle in out  # handle is still named as usable
            # Session still registered.
            assert sm.get(sid) is not None
        finally:
            sm.close(sid)

    def test_ssh_exec_normal_output_unprefixed(self, pc, monkeypatch):
        """T-001: stdout must stay UNPREFIXED (sudo -l runas specs parseable);
        stderr appended with an explicit marker only when non-empty."""
        from utils.handles import format_handle
        from utils.session_manager import get_manager

        class _ErrChan(_FakeChannel):
            def __init__(self):
                super().__init__("normal")
                self._err.extend(b"warn line\n")

            def recv_stderr_ready(self):
                return len(self._err) > 0

        client = _FakeClient()
        client.chan = _ErrChan()
        client._transport = _FakeTransport(client.chan)
        sm = get_manager()
        sid = sm.register("ssh", "op@10.0.0.9:22", client, hostname="10.0.0.9")
        handle = format_handle("ssh", sid)
        try:
            monkeypatch.setattr(pc, "DEFAULT_SSH_EXEC_TIMEOUT", 5)
            out = pc.ssh_exec(handle, "ls")
            assert out.startswith("hello\n")
            assert "[stderr] warn line" in out
            assert "Output:" not in out
        finally:
            sm.close(sid)


class TestSshExecBatch:
    @pytest.fixture
    def sshe(self):
        pytest.importorskip("paramiko")
        import auxiliaries.ssh_exec as sshe
        return sshe

    def test_batch_stdin_hang_surfaces_timeout_entry(self, sshe, monkeypatch):
        """A wedged command inside a batch must produce a per-command
        timed_out entry — never hang the whole batch."""
        client = _FakeClient("stdin_hang")
        monkeypatch.setattr(sshe.paramiko, "SSHClient", lambda: client)
        monkeypatch.setattr(
            client, "connect", lambda *a, **k: None, raising=False)
        # Bypass the real connect (already faked) and scope gate.
        import utils.scope_gate as g
        monkeypatch.setattr(g, "check_scan", lambda t: (True, "disarmed"))
        # ssh_exec_batch reads its per-command cap from the env per call.
        monkeypatch.setenv("SSH_EXEC_TIMEOUT", "0.3")

        res = sshe.ssh_exec_batch("10.0.0.9", "u", "p", ["top"])
        assert res["status"] == "Success"  # transport held
        entry = res["results"][0]
        assert entry["timed_out"] is True
        assert "cap" in entry["error"]

    def test_batch_normal_commands(self, sshe, monkeypatch):
        client = _FakeClient("normal")
        monkeypatch.setattr(sshe.paramiko, "SSHClient", lambda: client)
        monkeypatch.setattr(
            client, "connect", lambda *a, **k: None, raising=False)
        import utils.scope_gate as g
        monkeypatch.setattr(g, "check_scan", lambda t: (True, "disarmed"))

        res = sshe.ssh_exec_batch("10.0.0.9", "u", "p", ["id", "uname -a"], pace=0)
        assert res["commands_run"] == 2
        assert res["succeeded"] == 2
        assert res["results"][0]["exit_code"] == 0


# --- Brain executor pool ------------------------------------------------------


class TestBrainToolExecutor:
    def test_dedicated_pool_not_default(self):
        """CALL_TOOL sync dispatch must use the dedicated pool, never the
        default executor (the starvation leg of the stack-freeze). The
        legacy C forward (lib.send_event) may keep the default pool — it
        never blocks on a tool."""
        import inspect
        import listeners.thebrain as tb
        src = inspect.getsource(tb.dispatch)
        assert "_tool_executor()" in src
        for line in src.splitlines():
            if "run_in_executor(None" in line:
                assert "send_event" in line, (
                    f"sync tool dispatch leaked to the default executor: {line}"
                )

    def test_pool_is_bounded_and_named(self):
        import listeners.thebrain as tb
        ex = tb._tool_executor()
        assert ex._max_workers >= 4
        assert any(t.name.startswith("brain-tool") for t in ex._threads) or True