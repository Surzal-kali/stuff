import paramiko
import asyncio
from constants import framework_tool

@framework_tool("Execute a command via SSH using Paramiko")
def paramiko_client(hostname: str, username: str, password: str, command: str):
    """
    Connects to a remote host via SSH and executes a command.
    
    Args:
        hostname: The target IP or hostname.
        username: SSH username.
        password: SSH password.
        command: The shell command to execute.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password, timeout=10)
        
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        client.close()
        
        if error:
            return f"Output: {output}\nError: {error}"
        return output
    except Exception as e:
        return f"SSH Connection Error: {e}"
