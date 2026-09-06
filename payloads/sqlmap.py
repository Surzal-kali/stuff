import shlex
import subprocess

from constants import framework_tool


@framework_tool("Run sqlmap against a target URL to test for SQL injection vulnerabilities.")
def run_sqlmap(target_url: str, options: str = ""):
    """Run sqlmap against the specified target URL with optional command-line options.

    Deliberately synchronous: both dispatchers run sync tools in a worker
    thread (run_in_executor / asyncio.to_thread), so keeping this blocking
    subprocess call synchronous is correct and avoids pinning the event loop.

    Uses shell=False with shlex.split on the options string so the target URL
    and options are passed as argv elements, not interpolated into a shell
    command. This mirrors the nmap/searchsploit wrappers and prevents shell
    injection through attacker-controlled input (sqlmap itself can fetch URLs
    that reflect user input).

    Args:
        target_url: The target URL to test for SQL injection.
        options: Additional sqlmap command-line options as a single string
            (e.g. "--batch --forms --risk=3"). Quoted sub-phrases are
            preserved by shlex.

    Returns:
        sqlmap stdout on success; on a non-zero exit the stdout is still
        returned (sqlmap prints findings to stdout even when it exits
        non-zero) with the stderr appended for diagnosis.
    """
    # -u takes the URL as its own argv element; never interpolate it into a
    # shell string.
    extra = shlex.split(options) if options else []
    command = ["sqlmap", "-u", target_url, *extra]
    try:
        # No check=True: sqlmap often exits non-zero when it finds an
        # injectable parameter or when --batch finds nothing, and we still
        # want the stdout in that case.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            return result.stdout
        # Surface stderr so the operator can diagnose, but keep stdout
        # (sqlmap prints findings there even on a non-zero exit).
        return f"{result.stdout}\n[sqlmap exit {result.returncode}] {result.stderr}".strip()
    except subprocess.TimeoutExpired:
        return f"sqlmap timed out after 600s on {target_url}"
    except FileNotFoundError:
        return "sqlmap binary not found on PATH; install sqlmap first."
    except Exception as e:
        return f"Error running sqlmap: {e}"