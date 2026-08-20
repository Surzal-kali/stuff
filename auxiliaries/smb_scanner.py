import asyncio
import importlib.util
from impacket.smbconnection import SMBConnection
from pathlib import Path

_FRAMING_PATH = Path(__file__).resolve().parent.parent / "framing.py"
_FRAMING_SPEC = importlib.util.spec_from_file_location("framing", _FRAMING_PATH)
if _FRAMING_SPEC is None or _FRAMING_SPEC.loader is None:
    raise ImportError(f"Unable to load framing module from {_FRAMING_PATH}")
_FRAMING = importlib.util.module_from_spec(_FRAMING_SPEC)
_FRAMING_SPEC.loader.exec_module(_FRAMING)
pack_message = _FRAMING.pack_message

class SMBScanner:
    def __init__(self, brain_socket="/tmp/brain.sock"):
        self.brain_socket = brain_socket

    async def report_to_brain(self, event_type, session_id, data):
        """Pipes the finding back to the Brain sidecar."""
        try:
            reader, writer = await asyncio.open_unix_connection(path=self.brain_socket)
            # Using your framing logic: event|session_id|data
            # We use a dummy session_id 0 for general recon events
            payload = f"{event_type}|0|{data}"
            
            writer.write(pack_message(payload.encode()))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[!] Brain reporting failed: {e}")

    def check_null_session(self, target, remote):
        """Attempts a Null Session connection to a target SMB share."""
        try:
            # timeout=2 to keep the scan moving
            conn = SMBConnection(target, target, remoteByName=False, timeout=2)
            # Attempt login with empty user and empty password
            conn.login('', '') 
            conn.logoff()
            return True
        except Exception:
            return False

    async def scan_subnet(self, targets: list):
        """Iterates through targets and reports vulnerabilities."""
        print(f"[*] Starting SMB Null Session scan on {len(targets)} targets...")
        for target in targets:
            # Run the blocking Impacket call in a thread to avoid freezing the loop
            loop = asyncio.get_event_loop()
            is_vuln = await loop.run_in_executor(None, self.check_null_session, target, "C$")
            
            if is_vuln:
                print(f"[+] Target {target} is vulnerable to Null Sessions!")
                await self.report_to_brain("vuln_found", 0, f"SMB_NULL_SESSION:{target}")
            else:
                print(f"[-] Target {target} secure.")

# Integration Example for bootstrap.py
async def run_smb_recon(targets):
    scanner = SMBScanner()
    await scanner.scan_subnet(targets)
