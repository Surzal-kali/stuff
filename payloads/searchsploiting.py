
import shlex
import subprocess
from constants import framework_tool
#this module will be our primary searchsploit module, it will be used to search for exploits using the local searchsploit CLI.
@framework_tool("Search for exploits using searchsploit")
def search_exploit(query):
    # Use searchsploit command line tool to search for exploits.
    #
    # searchsploit treats each argv as a separate search term combined with AND
    # (see https://www.exploit-db.com/searchsploit: "term1 [term2] ... [termN]").
    # Passing the whole `query` as a single argument would search for the literal
    # string "apache 2.4" instead of "apache" AND "2.4", yielding no results.
    # shlex.split respects quoted sub-phrases a caller may want kept literal.
    #
    # --disable-colour keeps ANSI escape codes out of the captured stdout so the
    # framework/secretary can parse and relay the text cleanly.
    try:
        terms = shlex.split(query) if isinstance(query, str) else list(query)
        if not terms:
            return "Error: empty search query"
        result = subprocess.run(
            ['searchsploit', '--disable-colour', *terms],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"
