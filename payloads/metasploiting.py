import subprocess

import asyncio
import os
from constants import TransportType
# [ ]TODO: Fix connection lost and auto startup issues.
import dotenv
from dotenv import load_dotenv

from listeners.thebrain import framework_tool

load_dotenv()

MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")


class MetasploitClient:
    def __init__(self, mcp_path="msfconsole"):
        self.mcp_path = mcp_path
        self.process = None

    async def _mirror_logs(self, process):
        """Reads stdout and stderr and writes them to a log file."""
        try:
            with open("/tmp/msfconsole_mcp.log", "a") as log_file:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    log_file.write(line.decode(errors="replace"))
                    log_file.flush()
        except Exception as e:
            print(f"Logging error: {e}")

    async def start_mcp(self):
        """
        Load and start MCP in the same Metasploit console session.
        """
        pwd = MSGRPC_PASSWORD
        try:
            # Prevent double launch: Check if msfconsole is already running
            proc = await asyncio.create_subprocess_shell(
                "pgrep -x msfconsole",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if stdout:
                print("[!] msfconsole is already running. Skipping launch.")
                # In a real scenario, you'd attach or assume it's healthy.
                # For now, we return a dummy process or handle the logic in bootstrap.
                return None

            # Log msfconsole output to a file and maintain pipe for reading
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

            if process.stdin is None:
                raise RuntimeError("Metasploit console stdin is unavailable")

            # Start a background task to mirror stdout to the log file
            asyncio.create_task(self._mirror_logs(process))

            # Give the console a moment to actually load
            await asyncio.sleep(5)

            self.process = process
            return process
        except Exception as e:
            print(f"An error occurred while trying to start MSF: {e}")
            return None

    # This one goes through the Brain's logic
    @framework_tool("Scan for MSF modules", transport=TransportType.BRAIN_DISPATCH)
    async def search_module(self, module_type, module_name):
        """
        Search for a Metasploit module by type and name.
        """
        if self.process is None:
            print("[!] Metasploit console is not running.")
            return None

        try:
            # Send the search command to the Metasploit console
            command = f"search {module_type} {module_name}\n"
            self.process.stdin.write(command.encode())
            await self.process.stdin.drain()

            # Read the output from the console
            await asyncio.sleep(2)  # Wait for the command to execute
            output = await self.process.stdout.read(4096)
            return output.decode()
        except Exception as e:
            print(f"An error occurred while searching for the module: {e}")
            return None

    # This one is tagged to use the direct RPC path
    @framework_tool("Directly execute MSF module", transport=TransportType.MCP_RPC)
    async def execute_module(self, module_path, options):
        """
        Execute a Metasploit module with specified options.
        """
        if self.process is None:
            print("[!] Metasploit console is not running.")
            return None

        try:
            # Construct the command to use the module and set options
            command = f"use {module_path}\n"
            for option, value in options.items():
                command += f"set {option} {value}\n"
            command += "run\n"

            # Send the command to the Metasploit console
            self.process.stdin.write(command.encode())
            await self.process.stdin.drain()

            # Read the output from the console
            await asyncio.sleep(5)  # Wait for the module to execute
            output = await self.process.stdout.read(4096)
            return output.decode()
        except Exception as e:
            print(f"An error occurred while executing the module: {e}")
            return None

    @framework_tool("Set a payload with specified options.")
    async def set_payload(self, payload_name, options):
        """
        Set a payload with specified options.
        """
        if self.process is None:
            print("[!] Metasploit console is not running.")
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
            await asyncio.sleep(2)  # Wait for the command to execute
            output = await self.process.stdout.read(4096)
            return output.decode()
        except Exception as e:
            print(f"An error occurred while setting the payload: {e}")
            return None

    @framework_tool("Retrieve the options for a given Metasploit module.")
    async def get_options(self, module_path):
        """
        Retrieve the options for a given Metasploit module.
        """
        if self.process is None:
            print("[!] Metasploit console is not running.")
            return None

        try:
            # Send the command to show options for the module
            command = f"use {module_path}\nshow options\n"
            self.process.stdin.write(command.encode())
            await self.process.stdin.drain()

            # Read the output from the console
            await asyncio.sleep(2)  # Wait for the command to execute
            output = await self.process.stdout.read(4096)
            return output.decode()
        except Exception as e:
            print(f"An error occurred while retrieving module options: {e}")
            return None