# End-to-End Test Guide: Metasploitable2

A manual end-to-end walkthrough of the framework against a deliberately
vulnerable target. The point is to exercise the **full organic chat flow**:
the operator speaks naturally to the secretary, watches it surface the right
tool, approves the execution gate, and reads the result - exactly as a real
session would go. Do not automate the prompts below; the value is in the
human-in-the-loop interaction and the semantic-discovery behavior.

---

## 1. Lab Setup

### 1.1 Metasploitable2 VM

1. Download the Metasploitable2 VMDK from Rapid7 (search "metasploitable2
   download").
2. Create a new VM in VirtualBox / GNOME Boxes / libvirt using the existing
   `Metasploitable2.vmdk` disk (do not install from ISO).
3. Attach a **host-only** network adapter only. No bridged adapter, no NAT,
   no internet egress - this VM is wide open by design.
4. Boot it. It DHCPs on the host-only subnet; the canonical address is
   `192.168.56.102` on the VirtualBox host-only `vboxnet0` (`192.168.56.0/24`).
   Confirm with `nmap -sn 192.168.56.0/24` from the attacker box.
5. Default login on the VM console (if you need to adjust networking):
   `msfadmin` / `msfadmin`.

### 1.2 Attacker box (where this framework runs)

- Same host-only subnet, e.g. `192.168.56.1`.
- Ollama running with `nomic-embed-text` and the chat model from
  `SECRETARY_MODEL` (default `gemma4:12b`).
- ChromaDB server reachable at `CHROMA_HOST:CHROMA_PORT` (default
  `localhost:9000`).
- Metasploit Framework installed, with `msfconsole` on `$PATH`.
- `searchsploit` (ships with Metasploit) on `$PATH`.
- Root or `CAP_NET_RAW` on the attacker box - required by `syn_scan`
  (`raw_scan.so` opens a `SOCK_RAW`).
- Python deps installed: `pip install -r requirements.txt`.

### 1.3 Framework bootstrap

From the framework root (`/home/surzal/stuff`):

```bash
# 1. Stand up sidecars: Brain socket, SSL server, API gateway, MSF RPC.
python bootstrap.py --daemon

# 2. Wait for /tmp/brain.sock to appear and msfconsole to load msgrpc on 55552.
#    Tail the logs to confirm:
tail -f /tmp/brain.log          # Brain sidecar
ss -lnt | grep 55552            # MSF RPC port
curl -s http://localhost:6000/  # API gateway (or hit any documented route)

# 3. Re-index the tool registry (clear first for a clean slate):
python -m daharness.core --clear

# 4. Enter the interactive secretary REPL - this is where the test runs:
python bootstrap.py
```

### 1.4 Pre-flight checks

Before starting the chat walkthrough, verify:

- `ls -l /tmp/brain.sock` exists and is a socket.
- `msfconsole` is running and `msgrpc` loaded (`ss -lnt | grep 55552`).
- `searchsploit apache` returns results (confirms the binary is present).
- `id -u` is `0` (or the process has `CAP_NET_RAW`) - otherwise step 2 below
  will report `raw socket access requires root`.
- The target is reachable: `ping -c1 192.168.56.102` (or `nmap -Pn -sn`).

Set a shell variable for convenience:

```bash
TARGET=192.168.56.102
```

The prompts below assume `192.168.56.102`; substitute your target IP.

---

## 2. End-to-End Chat Walkthrough

Run this **in the interactive secretary REPL** (`python bootstrap.py`).
Type each prompt verbatim (or paraphrase - that is the point of testing
semantic discovery). After each step, verify the pass signal before moving on.

Each row validates something specific about the framework, noted in the
"Validates" column.

### Phase A - Reconnaissance

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 1 | "Run a full port and service scan on 192.168.56.102" | `run_nmap` (LOCAL_FILE/BRAIN) | stdout lists ports 21, 22, 23, 25, 53, 80, 111, 139, 445, 512-514, 1099, 1524, 2049, 2121, 3306, 5432, 5900, 6000, 6667, 8009, 8180 | Subprocess execution; argparse-derived schema |
| 2 | "Do a raw SYN check on port 445 of the target" | `syn_scan` (BRAIN, C plugin) | returns `{"status":"open"}` (or the root/`CAP_NET_RAW` error if not elevated) | ctypes C plugin path + argtypes/restype |
| 3 | "Check the target for SMB null sessions" | `check_null_session` / `run_smb_recon` | returns `True` (Metasploitable2 permits null session) | impacket via BRAIN_DISPATCH; blocking call in worker thread |

### Phase B - Research

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 4 | "Search exploit-db for samba 3.0.20" | `search_exploit` | returns the `usermap_script` entry (EDB-34845 / 16320) | subprocess tool with shlex splitting |
| 5 | "Find metasploit modules for the vsftpd backdoor" | `search_module` | returns `exploit/unix/ftp/vsftpd_234_backdoor` | MSF RPC search; dict-structured result parsing |

### Phase C - Exploitation

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 6 | "Show me the options for that vsftpd module" | `get_options` | returns RHOSTS, etc. | MSF module option introspection |
| 7 | "Exploit the vsftpd backdoor on 192.168.56.102" | `execute_module` (MCP_RPC) | reports 1 new session with session ID | MSF execute + session-poll loop; `before/after` diff catches the new session |
| 8 | "Run 'id' on that new session" | `interact_session` | `uid=0(root)` | MSF session persistence across tool calls; write/read with retry |

### Phase D - Credential access & post-exploitation

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 9 | "SSH to the target as msfadmin with password msfadmin" | `ssh_connect` | returns a `sess-NNNN` session_id | paramiko + SessionManager registration |
| 10 | "Run 'cat /etc/shadow' on that session" | `ssh_exec` | shadow contents for root, msfadmin, user, postgres... | SessionManager retrieval reuses the live SSHClient (no re-auth) |
| 11 | "Show all my active sessions" | `list_sessions` (paramiko) | lists both the SSH session and (if still alive) the MSF session | cross-tool session visibility |

### Phase E - Listeners, memory, logs

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 12 | "Start a TCP listener on port 4444" | `listen` | returns immediately with the bound address; the REPL does NOT hang | non-blocking service pattern (`serve_forever` in a background task) |
| 13 | "Remember that the root password on this box is toor" | `remember` | stored confirmation | ChromaDB namespaced vector memory write |
| 14 | "What did we find about port 21 earlier?" | `recall` | returns the vsftpd finding from step 7 | vector similarity recall across the session |
| 15 | "Show me recent brain logs" | `log_reader` | tail of `/tmp/brain.log` | log-reading tool via BRAIN_DISPATCH |

### Phase F - Cleanup

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| 16 | "Close all my sessions" | `ssh_close` + `close_msf_session` | both sessions report closed | session teardown on both managers |

---

## 3. Framework behaviors to watch for during the walkthrough

These are the things the end-to-end test is really validating, beyond whether
Metasploitable2 gets popped. Watch for them explicitly:

- **Semantic discovery:** each vague prompt surfaces the *correct* tool_id,
  not just any tool. A wrong surface is a registry/embedding quality bug.
- **Grounding rule:** if at any point the secretary tries `execute_tool` with
  a `tool_id` it never surfaced (no prior `search_tools`), it must be
  rejected. If you see it succeed, that is a grounding-rule regression.
- **Approval gate:** every execution pauses and shows the full manifest +
  arguments. A step that runs without pausing is a missing
  `requires_approval=True`.
- **Session persistence:** step 10 must reuse the connection from step 9 -
  if you see "session not found," SessionManager is broken or the call
  landed in a different process (Brain died and fell back in-process; see
  AGENTS.md "Process-local sessions" pitfall).
- **MSF session polling:** step 7 must report the new session. If it says
  "No new sessions detected," the poll window (`MSF_SESSION_POLL_SECONDS`)
  is too short or the `before/after` diff logic regressed.
- **Non-blocking listener:** step 12 returns immediately. If the REPL
  freezes, `listen` is calling `serve_forever` on the dispatcher loop.
- **Brain vs in-process:** optionally kill the Brain (`pkill -f thebrain.py`)
  mid-walkthrough and rerun step 10 - the SSH call should fall back to
  in-process execution but the SessionManager session created on the Brain
  will be invisible (expected, documented pitfall).

---

## 4. Coverage and known gaps

The walkthrough above covers the existing tool surface. Metasploitable2
exposes additional services beyond what the original modules exercised; the
sqlmap (§4.1) and impacket (§4.2) suites have been added to close most of
that gap. The remaining tools in `mainideas.txt` (§4.3) are general framework
completeness rather than Metasploitable2-specific.

### 4.1 sqlmap (added)

Metasploitable2 hosts vulnerable web apps on ports 80 and 8180 (DVWA,
Mutillidae, phpMyAdmin, Tomcat manager). `nmap` finds the port; `run_sqlmap`
(`payloads/sqlmap.py`, BRAIN_DISPATCH) follows through with SQLi testing.
Extend the walkthrough with:

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Validates |
|---|---|---|---|---|
| W1 | "Test for SQL injection on http://192.168.56.102/mutillidae/index.php?page=user-info.php&username=test&password=test in batch mode" | `run_sqlmap` | sqlmap reports at least one injectable parameter (e.g. `username`, `password`) | subprocess tool; argv (no shell); non-zero exit still returns stdout with findings |
| W2 | "Dump the accounts table from the mutillidae database on that URL in batch mode" | `run_sqlmap` (options `--batch -D mutillidae -T accounts --dump`) | sqlmap returns dumped credential rows | options string parsed via shlex; tool reuses the same URL arg |

Notes for the web-app phase:

- Always pass `--batch` (or include it in the prompt) - sqlmap otherwise
  pauses for interactive input, which would block the dispatcher worker
  until the 600s tool timeout fires.
- sqlmap runs `shell=False` with an argv list; quoting sub-phrases in
  `options` with shlex (e.g. `--forms`) is preserved.
- A non-zero exit does NOT mean failure here - sqlmap returns non-zero when
  it finds an injectable parameter, and the wrapper still returns the stdout
  containing the findings.

### 4.2 Impacket suite (added) - `auxiliaries/impacket_suite.py`

Six BRAIN_DISPATCH tools, two categories:

- **Programmatic SMB** (`SMBConnection`, works on Samba AND Windows):
  `smb_enum_shares`, `smb_read_file`.
- **Impacket script wrappers** (subprocess to `secretsdump.py` /
  `psexec.py` / `wmiexec.py` / `atexec.py`, argv + shell=False, `-no-pass`
  when no password, stdin closed): `secretsdump`, `psexec_exec`,
  `wmiexec_exec`, `atexec_exec`.

IMPORTANT - target compatibility: `psexec` (Service Control Manager), `wmiexec`
(WMI), `atexec` (Task Scheduler), and `secretsdump` remote mode target
Windows services/SAM that Samba does NOT implement. Against Metasploitable2
(a Samba host) they will fail with a protocol error - that is correct
behavior, not a framework bug. The winnable impacket step on Metasploitable2
is share enumeration, which pairs with the null-session finding in step 3.

| # | Prompt to secretary | Tool that should surface | Expected pass signal | Target |
|---|---|---|---|---|
| I0 | "Enumerate the SMB shares on 192.168.56.102 with a null session" | `smb_enum_shares` | lists shares (IPC$, a writable share, etc.) with read access | Metasploitable2 (winnable) |
| I0b | "Read the file 'etc/passwd' from the 'tmp' share on the target over null session" | `smb_read_file` | file contents returned (or a clean access-denied if the share isn't readable) | Metasploitable2 |
| I1 | "Use psexec to run 'whoami' on the target with null credentials" | `psexec_exec` | **expected to fail** with an SCM/protocol error against Samba - validates the tool surfaces, executes, and reports the incompatibility cleanly | Windows lab target to actually win |
| I2 | "Dump the SAM hashes from the target" | `secretsdump` | **expected to fail** against Samba with a SAM/registry error - validates surface + execute + clean failure | Windows lab target to actually win |

To fully exercise I1/I2 as wins, point them at a Windows lab VM (e.g. a
vulnerable Windows box with SMB + local-admin creds) instead of
Metasploitable2. `wmiexec_exec` and `atexec_exec` are alternative remote-exec
paths to try on the same Windows target.

### 4.3 Not covered by this target (general framework completeness)

- **burpsuite** - web app testing; Metasploitable2's apps could use it, but
  sqlmap covers the testable SQLi surface here.
- **hydra** - multi-protocol brute force; Metasploitable2 has VNC
  (password), Telnet, proftpd. Would add a brute-force phase.
- **john / hashcat** - password cracking; useful after step 10 grabs
  `/etc/shadow`, but not required to prove the framework's core flow.
- **ghidra** - reverse engineering; no target binary on Metasploitable2.
  General framework completeness, not part of this walkthrough.

---

## 5. Manual pass/fail checklist

After the walkthrough, confirm each:

- [ ] All 16 existing-tool prompts surfaced the expected tool (steps 1-16).
- [ ] No tool executed without an approval pause.
- [ ] No unsurfaced tool_id was executed (grounding rule held).
- [ ] Step 7 reported a new MSF session; step 8 returned `uid=0`.
- [ ] Step 10 reused the SSH connection from step 9 (no re-auth).
- [ ] Step 12 returned without freezing the REPL.
- [ ] Step 14 recalled the step 7 finding via vector similarity.
- [ ] Step 16 closed both the SSH and MSF sessions.
- [ ] (Optional) Brain-kill fallback: step 10 still executes in-process after
      `pkill -f thebrain.py`, with the expected "session not found" if the
      SSH session was Brain-local.

If any checkbox fails, note the step number and the observed behavior - that
is the regression to fix before adding sqlmap/impacket steps to the matrix.
