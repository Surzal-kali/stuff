import os
import time
from constants import framework_tool

@framework_tool("Read framework logs (Brain and MSF)")
def read_logs(log_type: str, lines: int = 50):
    """
    Read the last N lines of the specified log file.
    
    Args:
        log_type: 'brain' for the Brain sidecar logs, 'msf' for the MSF console logs.
        lines: Number of lines to retrieve from the end of the file.
    """
    log_map = {
        "brain": "/tmp/brain.log",
        "msf": "/tmp/msfconsole_mcp.log"
    }
    
    path = log_map.get(log_type.lower())
    if not path:
        return f"Error: Invalid log_type '{log_type}'. Use 'brain' or 'msf'."
    
    if not os.path.exists(path):
        return f"Error: Log file {path} does not exist."
    
    try:
        with open(path, "r", errors="replace") as f:
            content = f.readlines()
            return "".join(content[-lines:])
    except Exception as e:
        return f"Error reading log file: {e}"


