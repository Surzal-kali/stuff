"""Paramiko SSH tools with persistent (hanging) session support.

The original ``paramiko_client`` was a one-shot: connect, run one command,
close.  That drops the connection the instant the tool call returns, so the
secretary can never run a *second* command on the same host without
re-authenticating.

The tools below split the lifecycle so a live ``SSHClient`` survives across
tool calls via the process-local :class:`~utils.session_manager.SessionManager`:

    ssh_connect   -> opens the connection, returns an "ssh:sess-NNNN" handle
    ssh_exec      -> runs a command on that handle's session
    ssh_shell     -> opens an interactive channel (for shells that need a pty)
    ssh_close     -> tears the session down
    list_sessions -> lists ALL active sessions across every namespace
                     (ssh, msf, listener) as typed handles

Layer 1 (typed handles): every session-returning tool yields a string of the
form ``"<kind>:<id>"`` (here ``"ssh:sess-0001"``).  Tools that consume a
session declare ``accepted_handle_kinds=["ssh"]`` so the registry refuses a
handle from another namespace *before* execution and tells the model which
tool to use instead.  This kills the "which session_id do I pass?" entanglement
where an MSF numeric session id and a paramiko ``sess-NNNN`` id are both
plausible-looking arguments to the wrong tool.

Note on very old SSH targets: targets whose SSH server only offers host-key
algorithms modern paramiko no longer accepts (e.g. Metasploitable2's OpenSSH
4.7 with ssh-rsa/ssh-dss host keys) cannot be connected to with paramiko and
are meant to be accessed over SSH via a Metasploit module (``ssh_login``),
which yields an ``msf:`` handle.  The typed-handle gate keeps that ``msf:``
session from being confused with a paramiko ``ssh:`` session, so no special
paramiko legacy handling is attempted here.

The one-shot ``paramiko_client`` is kept for backward compatibility.
"""

import paramiko
from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()


@framework_tool(
    "Open a persistent SSH connection and return a typed session handle "
    "(e.g. 'ssh:sess-0001'). The handle is passed to ssh_exec, ssh_shell, and "
    "ssh_close. Prefer this over Metasploit's ssh_login for a plain "
    "username/password login on a normally-speaking SSH server. (For a "
    "target whose SSH server only offers legacy host-key algorithms, use a "
    "Metasploit ssh_login module instead, which returns an 'msf:' handle.)"
)
def ssh_connect(hostname: str, username: str, password: str, port: int = 22):
    """
    Opens a persistent SSH connection to a remote host.

    Returns a typed session handle string like "ssh:sess-0001" that can be
    passed to ssh_exec, ssh_shell, and ssh_close for follow-up commands on
    the SAME connection without re-authenticating.

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
            allow_agent=False,
            look_for_keys=False,
        )
        target = f"{username}@{hostname}:{port}"
        sid = _sm.register("ssh", target, client, hostname=hostname, username=username)
        handle = format_handle("ssh", sid)
        return (
            f"SSH session established: {handle} ({target}). "
            f"Use this handle with ssh_exec / ssh_shell / ssh_close."
        )
    except Exception as e:
        return f"SSH Connection Error: {e}"


@framework_tool(
    "Execute a command on an existing SSH session. Pass the 'ssh:' handle "
    "returned by ssh_connect (e.g. 'ssh:sess-0001').",
    accepted_handle_kinds=["ssh"],
)
def ssh_exec(handle: str, command: str):
    """
    Runs a shell command on a previously opened SSH session.

    The connection stays open after the command returns so you can call
    ssh_exec again with the same handle.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect (e.g. 'ssh:sess-0001').
        command: The shell command to execute.
    """
    kind, sid = parse_handle(handle)
    session = _sm.get(sid)
    if session is None:
        return (
            f"SSH session {handle} not found. Call ssh_connect first, "
            "or use list_sessions to see active sessions."
        )
    try:
        stdin, stdout, stderr = session.client.exec_command(command)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        # T-001: Return stdout UNPREFIXED so tokens like the ``(root : root)``
        # runas spec from ``sudo -l`` are not buried behind an "Output:"
        # label that some consumers strip or mis-parse.  stderr is appended
        # with a clear ``[stderr]`` marker only when non-empty, preserving
        # the full stdout surface for parsing.
        if error:
            return f"{output}\n[stderr] {error}"
        return output
    except paramiko.SSHException as e:
        # The connection may have died remotely; surface it clearly.
        return f"SSH session {handle} error (connection may be dead): {e}"
    except Exception as e:
        return f"SSH exec error: {e}"


@framework_tool(
    "Open an interactive shell channel on an existing SSH session. Use this "
    "instead of ssh_exec when the remote command needs a PTY (sudo prompts, "
    "menus, anything that checks isatty). Pass the 'ssh:' handle.",
    accepted_handle_kinds=["ssh"],
)
def ssh_shell(handle: str, command: str, timeout: float = 10.0):
    """
    Sends a command to an interactive shell channel and reads the response.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect.
        command: The command to send to the shell.
        timeout: How long to wait for output (seconds).
    """
    kind, sid = parse_handle(handle)
    session = _sm.get(sid)
    if session is None:
        return f"SSH session {handle} not found. Call ssh_connect first."

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


@framework_tool(
    "Close an SSH session and release the connection. Pass the 'ssh:' handle.",
    accepted_handle_kinds=["ssh"],
)
def ssh_close(handle: str):
    """
    Closes and removes a persistent SSH session.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect.
    """
    kind, sid = parse_handle(handle)
    if _sm.close(sid):
        return f"Session {handle} closed."
    return f"Session {handle} not found."


@framework_tool(
    "List ALL active sessions across every namespace (ssh, msf, listener) "
    "as typed handles. Use this to see which sessions you currently hold "
    "and which tools to use on each. This is the single canonical way to "
    "inspect live sessions — do not use separate per-namespace listers."
)
def list_sessions():
    """
    Lists every active session the framework is holding, regardless of which
    tool created it.  Each line shows a typed handle and its target, grouped
    by namespace.  Pass the exact handle shown here to the matching tool
    (ssh_exec for ssh:, interact_session for msf:, close_listener for
    listener:).
    """
    sections = []

    # --- SessionManager: ssh, listener (all process-local) ---
    sm_sessions = _sm.list_sessions()
    ssh_lines = []
    listener_lines = []
    for s in sm_sessions:
        handle = format_handle(s["kind"], s["sid"])
        line = f"  {handle} -> {s['target']}"
        if s["kind"] == "listener":
            listener_lines.append(line)
        else:
            # ssh and any future process-local kinds land here.  Unknown
            # kinds still surface so the model is never blind to a session.
            ssh_lines.append(line)

    sections.append("SSH sessions:")
    sections.append("\n".join(ssh_lines) if ssh_lines else "  (none)")

    sections.append("Listener sessions:")
    sections.append("\n".join(listener_lines) if listener_lines else "  (none)")

    # --- Metasploit sessions (shared client, may live on the Brain) ---
    msf_lines = []
    try:
        from payloads.metasploiting import MetasploitClient

        client = getattr(MetasploitClient.get_instance(), "client", None)
        if client is not None:
            sessions = client.sessions.list
            for sid, info in sorted(sessions.items(), key=lambda kv: int(kv[0])):
                handle = format_handle("msf", str(sid))
                msf_lines.append(
                    f"  {handle} -> {info.get('target_host', '?')} "
                    f"({info.get('type', '?')})"
                )
    except Exception:
        # MSF not running / unreachable — report it explicitly so the model
        # knows the absence is real and not just an empty list.
        msf_lines.append("  (Metasploit client unavailable)")

    sections.append("MSF sessions:")
    sections.append("\n".join(msf_lines) if msf_lines else "  (none)")

    return "\n".join(sections)


# --- Backward-compatible one-shot (kept for callers that don't need a
#     persistent session) -----------------------------------------------

@framework_tool("Execute a single command via SSH using Paramiko (one-shot, no persistent session)")
def paramiko_client(hostname: str, username: str, password: str, command: str):
    """
    Connects to a remote host via SSH, executes a single command, and closes
    the connection immediately.  Legacy key negotiation is handled
    automatically (same fallback as ssh_connect).

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
        client.connect(
            hostname, username=username, password=password, timeout=10,
            allow_agent=False, look_for_keys=False,
        )
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8")
        error = stderr.read().decode("utf-8")
        client.close()

        if error:
            return f"Output: {output}\nError: {error}"
        return output
    except Exception as e:
        return f"SSH Connection Error: {e}"
