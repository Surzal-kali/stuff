import subprocess

import asyncio
import os

# [ ]TODO: Fix launch and variable authentication issues with msfconsole and msgrpc.
import dotenv
from dotenv import load_dotenv

load_dotenv()

MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")


class MetasploitClient:
    def __init__(self, mcp_path="msfconsole"):
        self.mcp_path = mcp_path
        self.process = None

    async def start_mcp(self):
        """
        Load and start MCP in the same Metasploit console session.
        """
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

            # Log msfconsole output to a file to diagnose MCP startup failures
            log_file = open("/tmp/msfconsole_mcp.log", "w")
            process = await asyncio.create_subprocess_exec(
                self.mcp_path,
                "-q -x",
                stdin=asyncio.subprocess.PIPE,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
            )

            if process.stdin is None:
                raise RuntimeError("Metasploit console stdin is unavailable")

            # Give the console a moment to actually load
            await asyncio.sleep(5)

            # Ensure password is string then encode the entire command
            pwd = (
                MSGRPC_PASSWORD
                if isinstance(MSGRPC_PASSWORD, str)
                else MSGRPC_PASSWORD.decode("utf-8", errors="ignore")
            )
            cmd = f"load msgrpc -P {pwd} -S 55552\n"
            process.stdin.write(cmd.encode("utf-8"))
            await process.stdin.drain()
            await asyncio.sleep(5)

            self.process = process
            return process
        except Exception as e:
            print(f"An error occurred while trying to start MSF: {e}")
            return None
