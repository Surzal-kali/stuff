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
            ok = await self.start_mcp()
            if not ok:
                print(
                    "[!] Metasploit RPC could not be started (msfconsole may "
                    "not be running or msgrpc failed to load)."
                )
                return False
        return True

    async def start_mcp(self):
        """
        Load and start msgrpc in the Metasploit console session.
        """
        pwd = MSGRPC_PASSWORD
        try:
            # We check if msfconsole is running to ensure we can connect
            proc = await asyncio.create_subprocess_shell(
                "pgrep -x msfconsole",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if not stdout:
                print("[i] msfconsole is not running; launching it...")
                # Launch msfconsole with msgrpc loaded
                process = await asyncio.create_subprocess_exec(
                    self.mcp_path,
                    "-q",
                    "-x",
                    f"load msgrpc Pass={pwd}",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                # Give it time to boot
                await asyncio.sleep(10)
            
            # Connect to the RPC interface
            # Default msgrpc port is usually 55552
            self.client = MsfRpcClient(password=pwd, port=55552)
            return True
        except Exception as e:
            print(f"An error occurred while trying to start MSF RPC: {e}")
            return False

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
            for option, value in options.items():
                # pymetasploit3 uses dict-style assignment (__setitem__),
                # not a set_option() method.
                module[option] = value

            # Execute the module (fires as a job, returns immediately).
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

        Args:
            session_id: The numeric ID of the MSF session (from list_sessions or execute_module).
            command: The command to execute within the session.
        """
        if not await self._ensure_running():
            return None

        try:
            # client.sessions.session(sid) returns a ShellSession or
            # MeterpreterSession object wrapping the live MSF session.
            # The session itself persists in MSF across calls.
            sid = str(session_id)
            sessions = self.client.sessions.list
            if sid not in sessions:
                return f"MSF session {session_id} not found. Call list_sessions to see active sessions."

            session = self.client.sessions.session(sid)

            # Both ShellSession and MeterpreterSession have write() + read().
            # write() appends a newline if missing; read() returns the output
            # buffer.  We write, wait briefly, then read.
            session.write(command)
            await asyncio.sleep(1.5)

            output = session.read()
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")

            # If no output yet, try once more after a longer wait (meterpreter
            # can be slow to respond).
            if not output or not output.strip():
                await asyncio.sleep(2.0)
                output = session.read()
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")

            return output if output else f"(no output from session {session_id})"
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