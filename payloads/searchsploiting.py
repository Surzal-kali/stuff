
import subprocess
from constants import framework_tool
#this module will be our primary searchsploit module, it will be used to search for exploits using the local searchsploit CLI.
@framework_tool("Search for exploits using searchsploit")
def search_exploit(query):
    # Use searchsploit command line tool to search for exploits
    try:
        result = subprocess.run(['searchsploit', query], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"