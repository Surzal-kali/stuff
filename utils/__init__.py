from .packetcraft import PacketCraft, PacketUtils
from .sessions import DatabaseManager
from .session_manager import SessionManager, get_manager
import subprocess
import sys
__all__ = ['PacketCraft', 'PacketUtils', 'DatabaseManager', 'SessionManager', 'get_manager']



def compile_ssl_server(ip, port):
    """Compile the SSL server using make."""
    try:
        subprocess.run(["make", "-C", "ssl_server"], check=True)
        print("[+] SSL server compiled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error compiling SSL server: {e}")
        sys.exit(1)
    