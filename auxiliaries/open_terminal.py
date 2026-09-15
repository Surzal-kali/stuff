"""Open Terminal workbench integration: a network-isolated container the
secretary can use as a sandboxed execution environment for side tasks the
framework's native tools don't cover — data processing, script writing,
file analysis, document conversion, arbitrary code execution, etc.

The terminal container runs Open Terminal (https://openterminal.sh) in Docker
with an iptables firewall that blocks all outbound traffic except ChromaDB
and the Ollama embedding server.  The agent cannot bypass the framework's
scope layer through the terminal — nmap/masscan/amass installed inside the
container are physically unable to reach external targets.

Tools exposed (all BRAIN_DISPATCH, discovered by the Brain sidecar):

- ``terminal_exec``      — run a command (blocking, waits up to N seconds)
- ``terminal_status``    — poll a long-running command's output
- ``terminal_kill``      — kill a running command
- ``terminal_write_file`` — create/overwrite a file in the workspace
- ``terminal_read_file`` — read a file (with optional line range)
- ``terminal_list_files`` — list directory contents
- ``terminal_grep``     — search file contents (regex or literal)
- ``terminal_search``   — find files by glob pattern

Configuration (env vars, with defaults):

- ``OPEN_TERMINAL_URL``      — base URL of the terminal API (``http://localhost:8000``)
- ``OPEN_TERMINAL_API_KEY``  — API key for authentication
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests

from constants import framework_tool

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_BASE_URL = os.getenv("OPEN_TERMINAL_URL", "http://localhost:8000").rstrip("/")
_API_KEY = os.getenv("OPEN_TERMINAL_API_KEY", "")

_SESSION = requests.Session()
_SESSION.headers.update({"Authorization": f"Bearer {_API_KEY}"})

# Default wait for terminal_exec: long enough for most commands, short enough
# not to hold the secretary turn open excessively.  The secretary can override
# with the ``wait`` argument for long-running commands.
_DEFAULT_WAIT = 30

# Workspace root inside the terminal container.  The terminal API server runs
# with cwd /app (root-owned), so relative paths sent to it resolve against /app
# instead of the user workspace.  _abs() normalizes relative paths to here.
_WORKSPACE = "/home/user"


def _abs(path: str) -> str:
    """Normalize relative paths to the container workspace (server cwd is /app)."""
    return path if path.startswith("/") else f"{_WORKSPACE}/{path.lstrip('/')}"


def _post(path: str, json_body: dict) -> Dict[str, Any]:
    """POST to the terminal API and return a structured result dict."""
    try:
        r = _SESSION.post(f"{_BASE_URL}{path}", json=json_body, timeout=120)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"error": "terminal_unreachable", "detail": f"Cannot connect to {_BASE_URL}"}
    except requests.exceptions.Timeout:
        return {"error": "timeout", "detail": "Terminal API request timed out"}
    except requests.exceptions.HTTPError as e:
        return {"error": "http_error", "status": e.response.status_code, "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": "unexpected", "detail": str(e)[:500]}


def _get(path: str, params: Optional[dict] = None) -> Dict[str, Any]:
    """GET from the terminal API and return a structured result dict."""
    try:
        r = _SESSION.get(f"{_BASE_URL}{path}", params=params, timeout=120)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"error": "terminal_unreachable", "detail": f"Cannot connect to {_BASE_URL}"}
    except requests.exceptions.Timeout:
        return {"error": "timeout", "detail": "Terminal API request timed out"}
    except requests.exceptions.HTTPError as e:
        return {"error": "http_error", "status": e.response.status_code, "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": "unexpected", "detail": str(e)[:500]}


def _delete(path: str) -> Dict[str, Any]:
    """DELETE on the terminal API."""
    try:
        r = _SESSION.delete(f"{_BASE_URL}{path}", timeout=30)
        r.raise_for_status()
        return {"status": "ok"}
    except requests.exceptions.ConnectionError:
        return {"error": "terminal_unreachable", "detail": f"Cannot connect to {_BASE_URL}"}
    except Exception as e:
        return {"error": "unexpected", "detail": str(e)[:500]}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@framework_tool(
    "Execute a shell command in the network-isolated terminal workbench "
    "container.  The container has Python, git, nmap, radare2, searchsploit, "
    "and other tools installed but CANNOT reach external network targets "
    "(firewall blocks all outbound except internal services).  Use this for "
    "offline side tasks: running scripts, processing files, analyzing data, "
    "parsing output, generating reports.  Waits up to ``wait`` seconds for "
    "the command to finish and returns stdout/stderr inline.  If the command "
    "is still running after the wait, returns a process_id — poll it with "
    "terminal_status.",
    next_hints=["terminal_status"],
)
def terminal_exec(
    command: str,
    wait: int = 30,
    cwd: str = "",
) -> Dict[str, Any]:
    """Run a command in the terminal workbench.

    Args:
        command: Shell command to execute. Supports chaining (&&, ||, ;),
            pipes (|), and redirections.
        wait: Seconds to wait for the command to finish. If it completes in
            time, output is included inline. If still running after this,
            a process_id is returned for polling. Set to 0 for fire-and-forget.
        cwd: Working directory for the command (empty = default workspace).

    Returns:
        Dict with command output (stdout, stderr, exit_code) if finished,
        or process_id if still running after ``wait`` seconds.
    """
    body: Dict[str, Any] = {"command": command}
    if cwd:
        body["cwd"] = _abs(cwd)
    params = {"wait": wait if wait > 0 else None}
    try:
        r = _SESSION.post(
            f"{_BASE_URL}/execute", json=body, params=params, timeout=wait + 30
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"error": "terminal_unreachable", "detail": f"Cannot connect to {_BASE_URL}"}
    except requests.exceptions.Timeout:
        return {"error": "timeout", "detail": f"Terminal did not respond within {wait+30}s"}
    except requests.exceptions.HTTPError as e:
        return {"error": "http_error", "status": e.response.status_code, "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": "unexpected", "detail": str(e)[:500]}


@framework_tool(
    "Poll the status and output of a command launched by terminal_exec that "
    "did not finish within the wait window.  Returns stdout, stderr, exit "
    "code, and whether the process is still running.",
    next_hints=["terminal_kill", "terminal_exec"],
)
def terminal_status(process_id: str) -> Dict[str, Any]:
    """Get the status and output of a running or completed command.

    Args:
        process_id: The process_id returned by terminal_exec.
    """
    return _get(f"/execute/{process_id}/status")


@framework_tool(
    "Kill a command running in the terminal workbench by its process_id.",
)
def terminal_kill(process_id: str) -> Dict[str, Any]:
    """Kill a running command in the terminal.

    Args:
        process_id: The process_id returned by terminal_exec.
    """
    return _delete(f"/execute/{process_id}")


@framework_tool(
    "Write a file to the terminal workbench filesystem.  Parent directories "
    "are created automatically.  Use this to stage scripts, configs, or data "
    "files for the terminal to process.",
    next_hints=["terminal_exec"],
)
def terminal_write_file(
    path: str,
    content: str,
) -> Dict[str, Any]:
    """Create or overwrite a file in the terminal workspace.

    Args:
        path: Absolute or relative path. Parent dirs are auto-created.
        content: Text content to write.
    """
    return _post("/files/write", {"path": _abs(path), "content": content})


@framework_tool(
    "Read a file from the terminal workbench filesystem.  Supports reading "
    "a specific line range (1-indexed, inclusive).  Use this to inspect "
    "output files, logs, or scripts the terminal has produced.",
    next_hints=["terminal_exec"],
)
def terminal_read_file(
    path: str,
    start_line: int = 0,
    end_line: int = 0,
) -> Dict[str, Any]:
    """Read a file from the terminal workspace.

    Args:
        path: Path to the file to read.
        start_line: First line to return (1-indexed, inclusive). 0 = beginning.
        end_line: Last line to return (1-indexed, inclusive). 0 = end.
    """
    params: Dict[str, Any] = {"path": _abs(path)}
    if start_line > 0:
        params["start_line"] = start_line
    if end_line > 0:
        params["end_line"] = end_line
    return _get("/files/read", params=params)


@framework_tool(
    "List the contents of a directory in the terminal workbench.  Returns "
    "files and subdirectories with their types and sizes.",
)
def terminal_list_files(directory: str = ".") -> Dict[str, Any]:
    """List directory contents in the terminal workspace.

    Args:
        directory: Directory path to list (default: workspace root).
    """
    return _get("/files/list", params={"directory": _abs(directory)})


@framework_tool(
    "Search file contents in the terminal workbench using grep.  Supports "
    "regex or literal matching, case-insensitive mode, and glob file "
    "filters.  Returns matching lines with line numbers or just filenames.",
)
def terminal_grep(
    query: str,
    path: str = ".",
    regex: bool = True,
    case_insensitive: bool = False,
    include: str = "",
    max_results: int = 100,
) -> Dict[str, Any]:
    """Search file contents in the terminal workspace.

    Args:
        query: Text or regex pattern to search for.
        path: Directory or file to search in (default: workspace root).
        regex: Use regex matching (default true). Set false for literal.
        case_insensitive: Case-insensitive matching.
        include: Glob patterns to filter files (e.g. '*.py').
        max_results: Maximum matches to return.
    """
    params: Dict[str, Any] = {
        "query": query,
        "path": _abs(path),
        "regex": str(regex).lower(),
        "case_insensitive": str(case_insensitive).lower(),
        "max_results": max_results,
    }
    if include:
        params["include"] = include
    return _get("/files/grep", params=params)


@framework_tool(
    "Find files in the terminal workbench by glob pattern.  Returns "
    "matching file paths.  Use this to locate output files, logs, or "
    "specific file types the terminal has created.",
    next_hints=["terminal_read_file"],
)
def terminal_search(
    pattern: str,
    path: str = ".",
) -> Dict[str, Any]:
    """Search for files by glob pattern in the terminal workspace.

    Args:
        pattern: Glob pattern (e.g. '*.json', 'output/*.txt').
        path: Directory to search in (default: workspace root).
    """
    return _get("/files/glob", params={"pattern": pattern, "path": _abs(path)})
