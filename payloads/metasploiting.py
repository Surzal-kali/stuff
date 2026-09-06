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
    @framework_tool("Scan for MSF modules", transport=TransportType.BRAIN_DISPATCH)
    async def search_module(self, module_type=None, module_name=None):
        """
        Search for a Metasploit module by type and name.
        """
        if not await self._ensure_running():
            return None

        try:
            # Use pymetasploit3 to search modules
            # search() returns a list of module objects
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

            # MSF RPC module.search returns a dict keyed by module type, e.g.:
            #   {'auxiliary': [{'path': 'auxiliary/scanner/ssh/ssh_login',
            #                   'name': 'SSH Login Check Scanner', ...}]}
            # NOT a list of objects with .name/.type attributes. Iterate the
            # dict structure to build a readable, flat result list.
            formatted_results = []
            if isinstance(results, dict):
                for mod_type, mod_list in results.items():
                    if not isinstance(mod_list, list):
                        # Single-module entry (dict) rather than a list
                        mod_list = [mod_list]
                    for mod in mod_list:
                        if isinstance(mod, dict):
                            path = mod.get('path', mod.get('name', '?'))
                            display = mod.get('name', path)
                            formatted_results.append(f"{path} ({mod_type}) — {display}")
                        else:
                            formatted_results.append(f"{mod} ({mod_type})")
            elif isinstance(results, list):
                for mod in results:
                    if isinstance(mod, dict):
                        path = mod.get('path', mod.get('name', '?'))
                        display = mod.get('name', path)
                        mtype = mod.get('type', '?')
                        formatted_results.append(f"{path} ({mtype}) — {display}")
                    elif hasattr(mod, 'name') and hasattr(mod, 'type'):
                        formatted_results.append(f"{mod.name} ({mod.type})")
                    else:
                        formatted_results.append(str(mod))
            else:
                return str(results)
            
            return "\n".join(formatted_results) if formatted_results else f"No modules found matching query: {query}"
        except Exception as e:
            print(f"An error occurred while searching for the module: {e}")
            return None

    # This one is tagged to use the direct RPC path
    @framework_tool("Directly execute an MSF module and report any sessions created", transport=TransportType.MCP_RPC)
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
            new_sessions = []
            deadline = _time.time() + MSF_SESSION_POLL_SECONDS
            while _time.time() < deadline:
                await asyncio.sleep(MSF_SESSION_POLL_INTERVAL)
                after = set(self.client.sessions.list.keys())
                new_sessions = sorted(after - before, key=int)
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
                return (
                    f"Module {module_path} executed. "
                    f"{len(new_sessions)} new session(s) created:\n"
                    + "\n".join(session_summaries)
                    + "\nUse interact_session with the session ID(s) above to run commands."
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

    @framework_tool("Set a payload with specified options.")
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

    @framework_tool("Retrieve the options for a given Metasploit module.")
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

    @framework_tool("List all active Metasploit sessions")
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

    @framework_tool("Interact with a specific Metasploit session (shell or meterpreter)")
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

    @framework_tool("Close/kill a specific Metasploit session")
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