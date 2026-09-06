"""Paramiko SSH tools with persistent (hanging) session support.

The original ``paramiko_client`` was a one-shot: connect, run one command,
close.  That drops the connection the instant the tool call returns, so the
secretary can never run a *second* command on the same host without
re-authenticating.

The new tools below split the lifecycle so a live ``SSHClient`` survives
across tool calls via the process-local :class:`~utils.session_manager.SessionManager`:

    ssh_connect   -> opens the connection, returns a session_id
    ssh_exec      -> runs a command on that session
    ssh_shell     -> opens an interactive channel (for shells that need a pty)
    ssh_close     -> tears the session down
    list_sessions -> lists ALL active sessions (ssh and otherwise)

The one-shot ``paramiko_client`` is kept for backward compatibility.
"""

import paramiko
from constants import framework_tool
from utils.session_manager import get_manager

_sm = get_manager()


@framework_tool("Open a persistent SSH connection and return a session_id")
def ssh_connect(hostname: str, username: str, password: str, port: int = 22):
    """
    Opens a persistent SSH connection to a remote host.

    Returns a session_id string (e.g. "sess-0001") that can be passed to
    ssh_exec, ssh_shell, and ssh_close for follow-up commands on the SAME
    connection without re-authenticating.

    Args:
        hostname: The target IP or hostname.
        username: SSH username.
        password: SSH password.
        port: SSH port (default 22).
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname,
            port=int(port),
            username=username,
            password=password,
            timeout=10,
        )
        target = f"{username}@{hostname}:{port}"
        sid = _sm.register("ssh", target, client, hostname=hostname, username=username)
        return f"SSH session established: {sid} ({target})"
    except Exception as e:
        return f"SSH Connection Error: {e}"


@framework_tool("Execute a command on an existing SSH session")
def ssh_exec(session_id: str, command: str):
    """
    Runs a shell command on a previously opened SSH session.

    The connection stays open after the command returns so you can call
    ssh_exec again with the same session_id.

    Args:
        session_id: The session_id returned by ssh_connect.
        command: The shell command to execute.
    """
    session = _sm.get(session_id)
    if session is None:
        return (
            f"Session {session_id} not found. Call ssh_connect first, "
            "or use list_sessions to see active sessions."
        )
    try:
        stdin, stdout, stderr = session.client.exec_command(command)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        if error:
            return f"Output: {output}\nError: {error}"
        return output
    except paramiko.SSHException as e:
        # The connection may have died remotely; surface it clearly.
        return f"SSH session {session_id} error (connection may be dead): {e}"
    except Exception as e:
        return f"SSH exec error: {e}"


@framework_tool("Open an interactive shell channel on an existing SSH session")
def ssh_shell(session_id: str, command: str, timeout: float = 10.0):
    """
    Sends a command to an interactive shell channel and reads the response.

    Use this instead of ssh_exec when the remote command needs a PTY
    (e.g. sudo prompts, menus, anything that checks isatty).

    Args:
        session_id: The session_id returned by ssh_connect.
        command: The command to send to the shell.
        timeout: How long to wait for output (seconds).
    """
    session = _sm.get(session_id)
    if session is None:
        return f"Session {session_id} not found. Call ssh_connect first."

    try:
        channel = session.client.get_transport().open_session()
        channel.get_pty()
        channel.invoke_shell()
        channel.settimeout(float(timeout))

        import time

        # Drain any banner/motd the server sends on connect.
        time.sleep(0.5)
        if channel.recv_ready():
            channel.recv(4096)

        channel.send(command + "\n")
        time.sleep(1)

        output = b""
        while channel.recv_ready():
            output += channel.recv(4096)

        channel.close()
        return output.decode("utf-8", errors="replace")
    except Exception as e:
        return f"SSH shell error: {e}"


@framework_tool("Close an SSH session and release the connection")
def ssh_close(session_id: str):
    """
    Closes and removes a persistent SSH session.

    Args:
        session_id: The session_id returned by ssh_connect.
    """
    if _sm.close(session_id):
        return f"Session {session_id} closed."
    return f"Session {session_id} not found."


@framework_tool("List all active persistent sessions")
def list_sessions():
    """
    Lists all active sessions (SSH, MSF, etc.) held by the session manager.
    Each entry shows the session_id, type, and target.
    """
    sessions = _sm.list_sessions()
    if not sessions:
        return "No active sessions."
    lines = []
    for s in sessions:
        lines.append(f"{s['sid']}: {s['kind']} -> {s['target']}")
    return "\n".join(lines)


# --- Backward-compatible one-shot (kept for callers that don't need a
#     persistent session) -----------------------------------------------

@framework_tool("Execute a single command via SSH using Paramiko (one-shot, no persistent session)")
def paramiko_client(hostname: str, username: str, password: str, command: str):
    """
    Connects to a remote host via SSH, executes a single command, and closes
    the connection immediately.

    For persistent sessions that survive across multiple commands, use
    ssh_connect + ssh_exec + ssh_close instead.

    Args:
        hostname: The target IP or hostname.
        username: SSH username.
        password: SSH password.
        command: The shell command to execute.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password, timeout=10)

        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8")
        error = stderr.read().decode("utf-8")
        client.close()

        if error:
            return f"Output: {output}\nError: {error}"
        return output
    except Exception as e:
        return f"SSH Connection Error: {e}"
