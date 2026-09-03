import subprocess

import asyncio 
import os
#[ ]TODO: integrate the metasploit framework mcp through subprocess calls and regex extraction. 

class MetasploitClient:
    def __init__(self, mcp_path="msfconsole"):
        self.mcp_path = mcp_path
        self.process = None

    async def start_mcp(self):
        """
        Load and start MCP in the same Metasploit console session.
        """
        try:
            # Log msfconsole output to a file to diagnose MCP startup failures
            # Using a context manager or explicit close later is better, but for a daemon
            # we keep the handle to the log file.
            log_file = open("/tmp/msfconsole_mcp.log", "w")
            process = await asyncio.create_subprocess_exec(
                self.mcp_path, '-q',
                stdin=asyncio.subprocess.PIPE,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True
            )

            if process.stdin is None:
                raise RuntimeError("Metasploit console stdin is unavailable")

            # Give the console a moment to actually load
            await asyncio.sleep(5)
            process.stdin.write(b"load mcp\n")
            await process.stdin.drain()
            await asyncio.sleep(5)
            process.stdin.write(b"mcp start\n")
            await process.stdin.drain()
            
            self.process = process
            return process
        except Exception as e:
            print(f"An error occurred while trying to start MCP: {e}")
            return None
    def extract_mcp_info(self, output):
        """
        This function extracts relevant information from the MCP output using regex.
        It looks for specific patterns in the output to gather useful data.
        """
        import re
        
        # Example regex pattern to extract information (adjust as needed)
        apitoken = r"Bearer\s+([A-Za-z0-9\-_]+)"
        msfpass = r"Pass:\s+([A-Za-z0-9\-_]+)"
        
        matches = re.findall(apitoken, output)
        matches.extend(re.findall(msfpass, output))
        return matches

