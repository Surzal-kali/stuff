"""Persistent SSH batch-exec auxiliary: one connection, multiple commands.

Per-command one-shot SSH scripts (``paramiko_client``'s legacy one-shot) burn
tool budget — each call is a fresh TCP connect + SSH handshake — and under
rate limiting they flood sshd with concurrent channel-open requests, causing
channel-open timeouts and handshake rejections.

This tool connects **once**, runs a list of commands on the **same transport**
with configurable **pacing** between channel opens, collects per-command
stdout / stderr / exit code, and closes the connection when done.  It is the
batch analogue of ``ssh_connect`` + repeated ``ssh_exec`` + ``ssh_close``,
collapsed into a single tool call so the secretary doesn't burn its tool
budget on session management for a straightforward "run these five commands"
request.

Design pattern = ``nmap.py``: allowlist (no shell metachar injection surface —
commands are passed verbatim to the remote shell, same as ``ssh_exec``),
structured envelope (returns a dict, not a raw string), fail-fast (connection
failure returns immediately with a clear error, no partial retry).

When to use this vs ``ssh_connect`` + ``ssh_exec``:
- **ssh_exec_batch** — you know all the commands up front and want them run
  in one shot with pacing.  No session handle to manage.
- **ssh_connect + ssh_exec** — you need to run commands interactively, deciding
  the next command based on the previous one's output.  The ``ssh:`` handle
  survives across tool calls.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

import paramiko

from constants import framework_tool


@framework_tool(
    "Connect to an SSH host once and run a batch of commands on the same "
    "connection, with pacing between commands to avoid sshd channel-open "
    "rate limiting. Use this instead of repeated one-shot SSH calls when "
    "you need to run several commands on one host — one TCP connect, one "
    "SSH handshake, then each command on a fresh channel over the shared "
    "transport, paced. Returns per-command stdout, stderr, and exit code. "
    "Closes the connection when done. For interactive command-decides-next-"
    "command flows, use ssh_connect + ssh_exec instead.",
    next_hints=["report_finding"],
)
def ssh_exec_batch(
    hostname: str,
    username: str,
    password: str,
    commands: List[str],
    port: int = 22,
    pace: float = 0.5,
) -> Dict[str, Any]:
    """Connect once, run multiple commands on the same SSH transport, close.

    Each command runs via ``exec_command`` on a fresh channel over the shared
    transport.  ``pace`` seconds elapse between commands to avoid flooding
    sshd with rapid channel-open requests (the failure mode that caused
    channel-open timeouts and handshake rejections with per-command one-shot
    scripts).

    Args:
        hostname: Target IP or hostname.
        username: SSH username.
        password: SSH password.
        commands: List of shell commands to execute, in order.
        port: SSH port (default 22).
        pace: Seconds to wait between commands (default 0.5). Set to 0
            for no pacing on fast local targets; increase to 1-2 for
            rate-limited sshd instances.
    """
    if not commands:
        return {
            "status": "Failed",
            "error": "No commands provided.",
            "results": [],
        }

    # Normalise: accept a single string as one command, or a JSON string.
    if isinstance(commands, str):
        import json

        stripped = commands.strip()
        if stripped.startswith("["):
            try:
                commands = json.loads(stripped)
            except json.JSONDecodeError:
                commands = [commands]
        else:
            commands = [commands]
    if not isinstance(commands, list) or not all(
        isinstance(c, str) for c in commands
    ):
        return {
            "status": "Failed",
            "error": (
                "'commands' must be a list of strings (or a single string). "
                "Got type that could not be normalised."
            ),
            "results": [],
        }

    client: paramiko.SSHClient | None = None
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
    except Exception as exc:
        return {
            "status": "Failed",
            "error": f"SSH connection to {username}@{hostname}:{port} failed: {exc}",
            "results": [],
        }

    results: List[Dict[str, Any]] = []
    try:
        for idx, command in enumerate(commands):
            try:
                stdin, stdout, stderr = client.exec_command(command)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                # recv_exit_status blocks until the command finishes; -1
                # means the channel closed before the exit code arrived.
                exit_code = stdout.channel.recv_exit_status()
                entry: Dict[str, Any] = {
                    "command": command,
                    "stdout": out,
                    "exit_code": exit_code,
                }
                if err:
                    entry["stderr"] = err
                results.append(entry)
            except paramiko.SSHException as exc:
                results.append(
                    {
                        "command": command,
                        "stdout": "",
                        "exit_code": -1,
                        "error": f"SSH channel error: {exc}",
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "command": command,
                        "stdout": "",
                        "exit_code": -1,
                        "error": f"Execution error: {exc}",
                    }
                )

            # Pace between commands (not after the last one).
            if pace > 0 and idx < len(commands) - 1:
                time.sleep(float(pace))
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass

    # Envelope: overall status is Success if the connection held, even if
    # individual commands returned non-zero exit codes (those are per-command
    # results, not transport failures).  A connection-level failure was
    # already returned above.
    succeeded = sum(1 for r in results if r.get("exit_code", -1) == 0)
    return {
        "status": "Success",
        "target": f"{username}@{hostname}:{port}",
        "commands_run": len(results),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "results": results,
    }
