from pydoc import Helper
import subprocess

import asyncio
import os
from constants import TransportType
# [ ]TODO: Fix connection lost and auto startup issues.
import dotenv
from dotenv import load_dotenv

from constants import framework_tool
from pymetasploit3.msfrpc import MsfRpcClient

load_dotenv()

MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")


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
        """Check if a live msgrpc RPC connection exists.
        
        Returns False if the client is not initialized.
        """
        if not hasattr(self, 'client') or self.client is None:
            print("[!] Metasploit RPC client is not initialized. Please ensure it was started during bootstrap.")
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

            # Format results for the model
            formatted_results = []
            for mod in results:
                formatted_results.append(f"{mod.name} ({mod.type})")
            
            return "\n".join(formatted_results)
        except Exception as e:
            print(f"An error occurred while searching for the module: {e}")
            return None

    # This one is tagged to use the direct RPC path
    @framework_tool("Directly execute MSF module", transport=TransportType.MCP_RPC)
    async def execute_module(self, module_path, options):
        """
        Execute a Metasploit module with specified options.
        """
        if not await self._ensure_running():
            return None

        try:
            # Use pymetasploit3 to select module and set options
            module = self.client.modules.load(module_path)
            for option, value in options.items():
                module.set_option(option, value)
            
            # Execute the module
            result = module.execute()
            return result
        except Exception as e:
            print(f"An error occurred while executing the module: {e}")
            return None

    @framework_tool("Set a payload with specified options.")
    async def set_payload(self, payload_name, options):
        """
        Set a payload with specified options.
        """
        if not await self._ensure_running():
            return None

        try:
            # Construct the command to set the payload and its options
            command = f"set PAYLOAD {payload_name}\n"
            for option, value in options.items():
                command += f"set {option} {value}\n"

            # Send the command to the Metasploit console
            self.process.stdin.write(command.encode())
            await self.process.stdin.drain()

            # Read the output from the console
            return await self._capture_output()
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
            module = self.client.modules.load(module_path)
            options = module.options
            return str(options)
        except Exception as e:
            print(f"An error occurred while retrieving options: {e}")
            return None
            # Read the output from the console
            await asyncio.sleep(2)
            output = await self.process.stdout.read(4096)
            return output.decode()
        except Exception as e:
            print(f"An error occurred while retrieving options: {e}")
            return None

    @framework_tool("List all active Metasploit sessions")
    async def list_sessions(self):
        """
        List all active Metasploit sessions.
        """
        if not await self._ensure_running():
            return None

        try:
            sessions = self.client.sessions.list
            if not sessions:
                return "No active sessions."
            
            session_list = [f"ID: {s.id}, Info: {s.info}" for s in sessions]
            return "\n".join(session_list)
        except Exception as e:
            print(f"An error occurred while listing sessions: {e}")
            return None

    @framework_tool("Interact with a specific Metasploit session")
    async def interact_session(self, session_id: int, command: str):
        """
        Send a command to a specific active Metasploit session.
        
        Args:
            session_id: The numeric ID of the session.
            command: The command to execute within the session.
        """
        if not await self._ensure_running():
            return None

        try:
            session = self.client.sessions.get(session_id)
            if not session:
                return f"Session {session_id} not found."
            
            result = session.write(command)
            return result
        except Exception as e:
            print(f"An error occurred while interacting with session {session_id}: {e}")
            return None