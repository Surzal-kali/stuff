import subprocess
from ..constants import TransportType, framework_tool
@framework_tool(doc="Run sqlmap against a target URL to test for SQL injection vulnerabilities.", transport=TransportType.LOCAL_FILE)
def run_sqlmap(target_url: str, options: str = ""):
    """
    Run sqlmap against the specified target URL with optional command-line options.

    Args:
        target_url (str): The target URL to test for SQL injection vulnerabilities.
        options (str): Additional command-line options for sqlmap.

    Returns:
        str: The output from the sqlmap command.
    """
    command = f"sqlmap -u {target_url} {options}"
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return f"Error running sqlmap: {e.stderr.decode('utf-8')}"