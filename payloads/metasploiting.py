import subprocess
import asyncio
import os
import time as _time
from constants import TransportType
import dotenv
from dotenv import load_dotenv

from constants import framework_tool
from pymetasploit3.msfrpc import MsfRpcClient

load_dotenv()

MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")

# How long execute_module polls for new sessions after firing the module.
# ssh_login / similar auxiliaries take a few seconds to connect and create
# a session; without polling, the tool returns before the session exists
# and the caller never learns the session ID.
MSF_SESSION_POLL_SECONDS = float(os.getenv("MSF_SESSION_POLL_SECONDS", "30"))
MSF_SESSION_POLL_INTERVAL = float(os.getenv("MSF_SESSION_POLL_INTERVAL", "2"))


class MetasploitClient:
    _shared: "MetasploitClient | None" = None

    def __init__(self, mcp_path="msfconsole"):
        self.mcp_path = mcp_path

    @classmethod
    def get_instance(cls) -> "MetasploitClient":
        """Return the shared client so bootstrap and in-process tool launches
        bind to the SAME msfconsole handle."""
        if cls._shared is None:
            cls._shared = cls()
        return cls._shared

    async def _ensure_running(self) -> bool:
        """Ensure a live msgrpc RPC connection exists, lazily starting one if needed.

        Returns False (and explains why) instead of silently returning None,
        which upstream used to report as 'Success'.
        """
        if not hasattr(self, 'client') or self.client is None:
            print("[i] No MSF RPC client on this instance; attempting lazy start...")
            await self.start_mcp()
            # start_mcp returns a Process or None (None when it reused an
            # already-running msfconsole, or on failure); success is signalled
            # by the client actually being populated, not by the return value.
            if not getattr(self, 'client', None):
                print(
                    "[!] Metasploit RPC could not be started (msfconsole may "
                    "not be running or msgrpc failed to load)."
                )
                return False
        return True

    async def _wait_for_port(self, host="127.0.0.1", port=55552,
                             timeout=90, interval=2):
        """Poll until the msgrpc TCP port accepts a connection.

        msfconsole can take 30-60+ seconds to boot and load the msgrpc plugin
        (especially on first run while it builds the module cache).  Connecting
        before the port is open causes MsfRpcClient.login() to fail with an
        auth/connection error that the 3-try retry in post_request cannot
        out-wait.  This poller gives the RPC server time to come up before we
        attempt authentication.
        """
        import socket as _socket
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            try:
                with _socket.create_connection((host, port), timeout=2):
                    return True
            except (ConnectionRefusedError, OSError, _socket.timeout):
                pass
            await asyncio.sleep(interval)
        return False

    async def start_mcp(self):
        """
        Load and start msgrpc in the Metasploit console session.
        """
        pwd = MSGRPC_PASSWORD
        try:
            # We check if msfconsole is running to ensure we can connect.
            # Use -f (full cmdline match) not -x (exact process-name match):
            # msfconsole is a Ruby script, so the kernel process name is
            # "ruby", and `pgrep -x msfconsole` would never match it.
            #
            # The pattern '[m]sfconsole' is a regex that matches the literal
            # string "msfconsole" (the [m] character class matches 'm'), but
            # the pattern text itself does NOT contain "msfconsole", so pgrep
            # cannot match its own command line or the shell running it.  This
            # avoids the self-match that caused start_mcp to think msfconsole
            # was already running and skip the launch.
            #
            # create_subprocess_exec (no shell) is used so there is no
            # intermediate bash process whose argv could be matched either.
            proc = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "[m]sfconsole",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            launched_process = None
            if not stdout:
                print("[i] msfconsole is not running; launching it...")
                # Launch msfconsole with msgrpc loaded
                launched_process = await asyncio.create_subprocess_exec(
                    self.mcp_path,
                    "-q",
                    "-x",
                    f"load msgrpc Pass={pwd}",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
            else:
                # msfconsole is already running, but it may NOT have msgrpc
                # loaded (e.g. a manually-started console).  If port 55552 is
                # not listening yet, we need to load the plugin ourselves.
                print("[i] msfconsole already running; checking for msgrpc port...")

            # Poll for the RPC port to come up before attempting to connect.
            # This replaces the fixed 10-second sleep that was too short for
            # cold boots, and also covers the "already running but no msgrpc"
            # case (the port simply never opens and we fail clearly).
            port = 55552
            ready = await self._wait_for_port(port=port)
            if not ready:
                print(
                    f"[!] msgrpc did not come up on port {port} within the "
                    f"timeout. If msfconsole was already running without "
                    f"msgrpc, load it manually:  load msgrpc Pass={pwd}"
                )
                self.client = None
                return launched_process

            # Connect to the RPC interface now that the port is confirmed open.
            self.client = MsfRpcClient(password=pwd, port=port)
            # Return the Process we own so bootstrap can reap it, or None if we
            # reused an already-running msfconsole (nothing for us to kill).
            return launched_process
        except Exception as e:
            print(f"An error occurred while trying to start MSF RPC: {e}")
            return None

    # This one goes through the Brain's logic
    @framework_tool(
        "Search for Metasploit modules by type and name. Use this to find "
        "exploits, auxiliaries, payloads, and post-exploitation modules "
        "matching a known vulnerability or service (e.g. vsftpd backdoor, "
        "ssh_login, samba usermap_script). Returns a JSON list of objects "
        "with a 'module_path' field — copy that value VERBATIM (including "
        "the type prefix, e.g. 'auxiliary/scanner/ssh/ssh_login') as the "
        "module_path argument to execute_module. Do not abbreviate or "
        "shorten the path.",
        transport=TransportType.BRAIN_DISPATCH,
    )
    async def search_module(self, module_type=None, module_name=None, limit=15):
        """
        Search for a Metasploit module by type and name.

        Args:
            module_type: Optional module type filter (exploit, auxiliary, payload, post).
            module_name: Module name or keyword to search for (e.g. 'ssh', 'vsftpd').
            limit: Maximum number of results to return (default 15). Caps
                   result size so the secretary model's context isn't flooded
                   with 50+ matches, which causes it to abbreviate paths.
        """
        if not await self._ensure_running():
            return None

        try:
            query = ""
            if module_type and module_name:
                query = f"type:{module_type} name:{module_name}"
            elif module_type:
                query = f"type:{module_type}"
            elif module_name:
                query = module_name
            else:
                return "Please provide either a module_type or a module_name to search."

            results = self.client.modules.search(query)

            if not results:
                return f"No modules found matching query: {query}"

            # Build a structured list with a clearly-labeled module_path
            # field. Returning JSON (instead of formatted text like
            # "path (type) — name") makes it much harder for the secretary
            # model to abbreviate or mangle the path when it passes it to
            # execute_module. The model copies a labeled JSON value far more
            # reliably than it parses and re-types a formatted string.
            structured = []
            if isinstance(results, dict):
                for mod_type, mod_list in results.items():
                    if not isinstance(mod_list, list):
                        mod_list = [mod_list]
                    for mod in mod_list:
                        if isinstance(mod, dict):
                            path = mod.get('path', mod.get('name', '?'))
                            structured.append({
                                "module_path": path,
                                "type": mod_type,
                                "name": mod.get('name', path),
                            })
                        else:
                            structured.append({
                                "module_path": str(mod),
                                "type": mod_type,
                                "name": str(mod),
                            })
            elif isinstance(results, list):
                for mod in results:
                    if isinstance(mod, dict):
                        path = mod.get('path', mod.get('name', '?'))
                        structured.append({
                            "module_path": path,
                            "type": mod.get('type', '?'),
                            "name": mod.get('name', path),
                        })
                    elif hasattr(mod, 'name') and hasattr(mod, 'type'):
                        structured.append({
                            "module_path": mod.name,
                            "type": mod.type,
                            "name": mod.name,
                        })
                    else:
                        structured.append({
                            "module_path": str(mod),
                            "type": "?",
                            "name": str(mod),
                        })
            else:
                return str(results)

            # Cap the result count so the model's context window isn't
            # overwhelmed by a long list (which causes abbreviation/truncation).
            max_results = int(limit) if limit else 15
            total = len(structured)
            if total > max_results:
                structured = structured[:max_results]

            if not structured:
                return f"No modules found matching query: {query}"

            return {
                "query": query,
                "total_matches": total,
                "returned": len(structured),
                "modules": structured,
                "note": "Use the 'module_path' value verbatim as the module_path argument to execute_module. Do not abbreviate.",
            }
        except Exception as e:
            print(f"An error occurred while searching for the module: {e}")
            return None

    # This one is tagged to use the direct RPC path
    @framework_tool(
        "Execute or fire a Metasploit exploit or auxiliary module against a "
        "target host. Use this to exploit a vulnerability (e.g. vsftpd "
        "backdoor, ssh_login, samba usermap_script) and obtain a shell or "
        "meterpreter session on the compromised target. Accepts the full "
        "module path (e.g. exploit/unix/ftp/vsftpd_234_backdoor) and a dict "
        "of options (RHOSTS, USERNAME, PASSWORD, PAYLOAD, LHOST, LPORT). "
        "The module_path MUST be the exact value returned by search_module's "
        "module_path field — do not abbreviate, shorten, or paraphrase it. "
        "Polls for new sessions and reports their IDs.",
        transport=TransportType.MCP_RPC,
    )
    async def execute_module(self, module_path, options):
        """
        Execute a Metasploit module with specified options.

        After execution, polls for newly-created sessions (shell/meterpreter)
        and returns their IDs so the caller can interact with them via
        interact_session.  This fixes the "connection dropped on success"
        issue: the module fires as a job, the session appears asynchronously,
        and without polling the tool returned before the session existed.

        Args:
            module_path: Full MSF module path, e.g. 'auxiliary/scanner/ssh/ssh_login'.
            options: Dict of option name -> value, e.g. {'RHOSTS': '10.0.0.5', 'USERNAME': 'root', 'PASSWORD': 'toor'}.
        """
        if not await self._ensure_running():
            return None

        try:
            # Record sessions that exist BEFORE execution so we can detect
            # new ones created by this module run.
            before = set(self.client.sessions.list.keys())

            # pymetasploit3 ModuleManager has use(mtype, mname), not load().
            # Split 'auxiliary/scanner/ssh/ssh_login' into type='auxiliary'
            # and name='scanner/ssh/ssh_login'.
            parts = module_path.split("/", 1)
            if len(parts) != 2:
                return f"Invalid module_path '{module_path}'. Expected 'type/name', e.g. 'auxiliary/scanner/ssh/ssh_login'."
            mtype, mname = parts[0], parts[1]
            module = self.client.modules.use(mtype, mname)

            # Type coercion: the secretary model passes all option values as
            # strings (from JSON), but pymetasploit3 enforces types — boolean
            # options raise TypeError if given "true"/"false" strings, and
            # integer options may misbehave with string numbers.  Inspect each
            # option against the module's option metadata and coerce.
            def _coerce(opt_name, opt_val, target_module):
                if opt_name not in target_module.options:
                    return opt_val  # payload-level option, handle separately
                # pymetasploit3 stores option metadata in _moptions
                mopt = target_module._moptions.get(opt_name, {})
                opt_type = mopt.get("type", "")
                if opt_type == "bool":
                    if isinstance(opt_val, str):
                        return opt_val.lower() in ("true", "1", "yes")
                    return bool(opt_val)
                elif opt_type == "integer":
                    try:
                        return int(opt_val)
                    except (ValueError, TypeError):
                        return opt_val
                return opt_val

            # CRITICAL: pymetasploit3 exploit modules do NOT accept PAYLOAD,
            # LHOST, or LPORT as regular datastore options (module['PAYLOAD']
            # raises KeyError).  These are payload-level options that must be
            # set on a PayloadModule object and passed to execute().  Worse,
            # calling execute() with no payload kwarg sets
            # DisablePayloadHandler=True — the exploit fires but never listens
            # for the reverse shell, so no session is ever created.
            #
            # The fix: if PAYLOAD is in the options, load it as a
            # PayloadModule, set LHOST/LPORT/etc. on it, and pass the
            # PayloadModule to execute().  pymetasploit3's execute() merges
            # the payload's runoptions (LHOST, LPORT, etc.) into the final
            # RPC call — this is the ONLY way those values reach MSF.
            opts = dict(options)  # copy so we don't mutate the caller's dict
            payload_name = opts.pop("PAYLOAD", None)

            # Set non-payload options on the module datastore first.
            # Check against module.options (the list of valid option names),
            # NOT `option in module` — __contains__ checks _runopts which is
            # the runtime datastore and may not contain options that haven't
            # been set yet, causing valid options like RHOSTS to be skipped.
            for option, value in opts.items():
                if option in module.options:
                    coerced = _coerce(option, value, module)
                    module[option] = coerced

            # CRITICAL: For exploit modules with a reverse payload, set
            # ExitOnSession=false so the handler job stays alive after the
            # first session connects.  The MSF default (ExitOnSession=true)
            # causes the handler to exit the instant a session is created;
            # for staged payloads (e.g. windows/meterpreter/reverse_tcp) the
            # stage transfer is still in flight when the handler dies, so the
            # TCP connection drops and the session closes within ~1 second.
            # The caller can still override this by passing ExitOnSession in
            # options, but the safe default is false.
            if mtype == "exploit" and payload_name and "ExitOnSession" in module.options:
                if "ExitOnSession" not in opts:
                    module["ExitOnSession"] = False
                # If the caller explicitly passed it, _coerce already set it
                # in the loop above.

            # Build the payload argument for execute().
            payload_arg = None
            if payload_name:
                # Load the payload as a PayloadModule so LHOST/LPORT can be
                # set on it.  pymetasploit3's execute() only merges payload
                # runoptions when it receives a PayloadModule, not a string.
                payload_mod = self.client.modules.use("payload", payload_name)
                # Set any payload-level options that the exploit module
                # didn't accept (LHOST, LPORT, LURI, etc.).
                for opt_name, opt_val in opts.items():
                    if opt_name not in module.options and opt_name in payload_mod.options:
                        coerced = _coerce(opt_name, opt_val, payload_mod)
                        payload_mod[opt_name] = coerced
                payload_arg = payload_mod

            # Execute the module (fires as a job, returns immediately).
            # For exploit modules with a payload, the handler is enabled and
            # LHOST/LPORT are properly set.  For auxiliaries, payload_arg is
            # None and execute() behaves normally.
            if payload_arg is not None:
                result = module.execute(payload=payload_arg)
            else:
                result = module.execute()

            # Poll for new sessions.  ssh_login and similar auxiliaries take
            # a few seconds to connect and create a session; without this
            # loop the tool returns before the session exists.
            #
            # We also track TRANSIENT sessions — session IDs that appeared
            # briefly and then vanished before the next poll.  This happens
            # when a session is created but dies almost immediately (staged
            # payload staging failure, AV killing the payload process, etc.).
            # Without this tracking, the loop would simply never see the
            # session and report "No new sessions detected", hiding the real
            # failure from the caller.
            new_sessions = []
            transient_sessions = set()
            seen_once = set()  # session IDs we observed at least once
            deadline = _time.time() + MSF_SESSION_POLL_SECONDS
            while _time.time() < deadline:
                await asyncio.sleep(MSF_SESSION_POLL_INTERVAL)
                after = set(self.client.sessions.list.keys())
                current_new = after - before
                # Detect sessions that appeared since the last poll but are
                # already gone — they were transient.
                gone = seen_once - after
                transient_sessions |= gone
                seen_once |= current_new
                new_sessions = sorted(current_new, key=int)
                if new_sessions:
                    break

            # Build a readable summary of any new sessions.
            session_summaries = []
            all_sessions = self.client.sessions.list
            for sid in new_sessions:
                info = all_sessions.get(sid, {})
                session_summaries.append(
                    f"  session {sid}: type={info.get('type', '?')} "
                    f"target={info.get('target_host', '?')} "
                    f"desc={info.get('desc', '?')}"
                )

            if session_summaries:
                msg = (
                    f"Module {module_path} executed. "
                    f"{len(new_sessions)} new session(s) created:\n"
                    + "\n".join(session_summaries)
                    + "\nUse interact_session with the session ID(s) above to run commands."
                )
                if transient_sessions:
                    msg += (
                        f"\n\n[!] WARNING: {len(transient_sessions)} additional "
                        f"session(s) were created but died immediately (IDs: "
                        f"{sorted(transient_sessions, key=int)}). This usually "
                        "means the staged payload's handler exited before the "
                        "stage transfer completed (ExitOnSession was true), or "
                        "the payload process was killed on the target (AV/EDR)."
                    )
                return msg
            elif transient_sessions:
                return (
                    f"Module {module_path} executed (job_id={result}). "
                    f"{len(transient_sessions)} session(s) were created but "
                    f"closed immediately (IDs: {sorted(transient_sessions, key=int)}). "
                    "The payload likely connected back but the session died "
                    "before stabilizing. Common causes:\n"
                    "  - Handler exited before staging completed (ExitOnSession)\n"
                    "  - AV/EDR killed the payload process on the target\n"
                    "  - Architecture/platform mismatch in the payload\n"
                    "  - Network instability dropping the reverse connection\n"
                    "Check the msfconsole log for details. Consider a stageless "
                    "payload or verify the payload architecture matches the target."
                )
            else:
                return (
                    f"Module {module_path} executed (job_id={result}). "
                    f"No new sessions detected within {MSF_SESSION_POLL_SECONDS:.0f}s. "
                    "The module may still be running; call list_sessions to check later."
                )
        except Exception as e:
            print(f"An error occurred while executing the module: {e}")
            return None

    @framework_tool(
        "Configure a Metasploit payload (e.g. cmd/unix/reverse, "
        "windows/meterpreter/reverse_tcp) with options like LHOST and LPORT. "
        "Use this to set up the payload before executing an exploit module."
    )
    async def set_payload(self, payload_name, options):
        """
        Configure a Metasploit payload with specified options.

        In the RPC model there is no global console 'set PAYLOAD' command;
        instead we load the payload module and apply options to it.  The
        configured payload can then be referenced by an exploit module via
        its PAYLOAD option (see execute_module).
        """
        if not await self._ensure_running():
            return None

        try:
            # Load the payload module via RPC so we can set options on it.
            # payload_name is expected as a path like 'cmd/unix/reverse_python'.
            module = self.client.modules.use("payload", payload_name)
            for option, value in options.items():
                module[option] = value
            return f"Payload '{payload_name}' configured with options: {options}\nAvailable options: {module.options}"
        except Exception as e:
            print(f"An error occurred while setting the payload: {e}")
            return None

    @framework_tool(
        "Show the available options and required parameters for a specific "
        "Metasploit module (e.g. RHOSTS, USERNAME, PAYLOAD, LHOST). Use this "
        "before executing a module to see what needs to be set."
    )
    async def get_options(self, module_path):
        """
        Retrieve the options for a given Metasploit module.
        """
        if not await self._ensure_running():
            return None

        try:
            # pymetasploit3 ModuleManager has use(mtype, mname), not load().
            parts = module_path.split("/", 1)
            if len(parts) != 2:
                return f"Invalid module_path '{module_path}'. Expected 'type/name', e.g. 'auxiliary/scanner/ssh/ssh_login'."
            mtype, mname = parts[0], parts[1]
            module = self.client.modules.use(mtype, mname)
            options = module.options
            return str(options)
        except Exception as e:
            print(f"An error occurred while retrieving options: {e}")
            return None

    @framework_tool(
        "List all active Metasploit sessions (shell and meterpreter). Shows "
        "session IDs, types, target hosts, and descriptions. Use this to "
        "check which sessions are alive after running exploit modules."
    )
    async def list_sessions(self):
        """
        List all active Metasploit sessions (shell and meterpreter).
        Shows session ID, type, target host, and description.
        """
        if not await self._ensure_running():
            return None

        try:
            sessions = self.client.sessions.list
            if not sessions:
                return "No active MSF sessions."

            lines = []
            for sid, info in sorted(sessions.items(), key=lambda kv: int(kv[0])):
                lines.append(
                    f"  ID: {sid}, Type: {info.get('type', '?')}, "
                    f"Target: {info.get('target_host', '?')}, "
                    f"Desc: {info.get('desc', '?')}"
                )
            return "Active MSF sessions:\n" + "\n".join(lines)
        except Exception as e:
            print(f"An error occurred while listing sessions: {e}")
            return None

    @framework_tool(
        "Run a command on an active Metasploit session (shell or meterpreter). "
        "Use this after execute_module creates a session to run commands like "
        "'id', 'whoami', 'cat /etc/shadow' on the compromised target. Pass the "
        "session ID and the command string. The session stays alive for "
        "follow-up commands."
    )
    async def interact_session(self, session_id, command):
        """
        Send a command to a specific active Metasploit session and read the
        response.  Works with both shell and meterpreter sessions.

        The session stays alive in MSF after this call returns, so you can
        call interact_session again with the same session_id for follow-up
        commands.

        For shell sessions, an exit-code marker is appended after the command
        so the caller can tell whether a command that produced no stdout (like
        'touch', 'mkdir', 'cp') actually succeeded.  The return string always
        includes an explicit success/failure indicator.

        Args:
            session_id: The numeric ID of the MSF session (from list_sessions or execute_module).
            command: The command to execute within the session.
        """
        if not await self._ensure_running():
            return None

        try:
            sid = str(session_id)
            sessions = self.client.sessions.list
            if sid not in sessions:
                return f"MSF session {session_id} not found. Call list_sessions to see active sessions."

            session = self.client.sessions.session(sid)
            session_type = sessions[sid].get("type", "")

            # --- Shell sessions: append an exit-code sentinel ---
            # A bare 'touch /tmp/foo' produces no stdout — read() returns just
            # the next prompt, which the LLM cannot interpret as success or
            # failure.  By echoing a unique sentinel with the exit code, we
            # can parse a definitive result regardless of stdout volume.
            if "shell" in session_type:
                sentinel = "__CMD_EXIT_CODE__"
                full_cmd = f"{command}; echo {sentinel}_$?_"
                session.write(full_cmd)
                await asyncio.sleep(2.0)

                output = session.read()
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")

                # Drain any remaining output (slow shells may still be writing).
                if sentinel not in output:
                    await asyncio.sleep(1.5)
                    more = session.read()
                    if isinstance(more, bytes):
                        more = more.decode("utf-8", errors="replace")
                    output += more

                # Parse the exit code sentinel: __CMD_EXIT_CODE___0_
                exit_code = None
                clean_output = output
                import re as _re
                m = _re.search(r"__CMD_EXIT_CODE__(?:_)?(\d+)(?:_)?", output)
                if m:
                    exit_code = int(m.group(1))
                    # Strip the sentinel and everything after it from the
                    # displayed output so the model sees only the command's
                    # actual stdout.
                    clean_output = output[:m.start()].strip()

                # Also strip a leading echo of the sentinel command if the
                # shell echoed it back (common in raw shells).
                if full_cmd in clean_output:
                    clean_output = clean_output.replace(full_cmd, "").strip()
                # Strip leading prompt artifacts.
                for prompt_char in ("$", "#", ">"):
                    if clean_output.startswith(prompt_char):
                        clean_output = clean_output[1:].lstrip()

                if exit_code is not None and exit_code == 0:
                    if clean_output:
                        return f"[SUCCESS exit=0] {clean_output}"
                    return f"[SUCCESS exit=0] Command completed with no stdout output (normal for touch/mkdir/cp/etc)."
                elif exit_code is not None:
                    return f"[FAILED exit={exit_code}] {clean_output or '(no stdout)'}"
                else:
                    # Sentinel not found — the command may still be running or
                    # the shell is unresponsive.  Return what we have.
                    return f"[UNKNOWN] Raw output: {output!r}"
            else:
                # --- Meterpreter sessions: use write/read directly ---
                session.write(command)
                await asyncio.sleep(2.0)

                output = session.read()
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")

                if not output or not output.strip():
                    await asyncio.sleep(2.0)
                    output = session.read()
                    if isinstance(output, bytes):
                        output = output.decode("utf-8", errors="replace")

                if output and output.strip():
                    return f"[OUTPUT] {output.strip()}"
                return f"[NO OUTPUT] Command sent to meterpreter session {session_id}; no stdout returned (may be normal for this command type)."
        except Exception as e:
            print(f"An error occurred while interacting with session {session_id}: {e}")
            return f"MSF session interaction error: {e}"

    @framework_tool(
        "Close and kill a specific Metasploit session by ID. Use this to "
        "clean up after exploitation when the session is no longer needed."
    )
    async def close_msf_session(self, session_id):
        """
        Kill and remove a Metasploit session.

        Args:
            session_id: The numeric ID of the MSF session to close.
        """
        if not await self._ensure_running():
            return None

        try:
            sid = str(session_id)
            sessions = self.client.sessions.list
            if sid not in sessions:
                return f"MSF session {session_id} not found."

            session = self.client.sessions.session(sid)
            # Both session types inherit stop() from MsfSession.
            session.stop()
            return f"MSF session {session_id} closed."
        except Exception as e:
            print(f"An error occurred while closing session {session_id}: {e}")
            return f"MSF session close error: {e}"