"""ffuf web fuzzer with background job + poll pattern.

ffuf directory / vhost / parameter fuzzing runs can take minutes to tens of
minutes depending on the wordlist size, rate limiting, and recursion depth.
A blocking ``subprocess.run`` holds the entire secretary turn open for the
run's full runtime and fights the turn timeout.  Instead, this module uses
the shared :mod:`utils.background_job` helper:

- ``run_ffuf(url, wordlist, options)`` launches ffuf as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id`` plus a log
  file path.  The secretary turn is NOT held open.
- ``ffuf_status(job_id)`` polls the job: checks whether the process is
  still alive, tails the log, and parses a summary of discovered paths /
  responses so the model can decide whether to keep polling or proceed to
  the next tool.

This mirrors the proven nmap ``run_nmap`` / ``nmap_status`` shape and
inherits the shared ``BackgroundJob`` machinery.

Non-interactivity is enforced defensively: ``-noninteractive`` is
auto-injected when the caller omits it (ffuf otherwise opens an interactive
console on SIGINT/TTY that blocks the detached subprocess), and ``stdin``
is ``/dev/null`` via the shared launcher as a second defense.
"""

from __future__ import annotations

import json as _json
import re
from typing import Any, Dict, List

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job


# Standard ffuf result-row format, e.g.:
#   [Status: 200, Size: 1234, Words: 56, Lines: 12, Duration: 0.001s]: /admin
_FFUF_ROW_RE = re.compile(
    r"\[Status:\s*(?P<status>\d+),\s*"
    r"Size:\s*(?P<size>\d+),\s*"
    r"Words:\s*(?P<words>\d+),\s*"
    r"Lines:\s*(?P<lines>\d+)"
    r"(?:,\s*Duration:\s*(?P<duration>[\d.]+s))?"
    r"\]:\s*(?P<path>.+?)\s*$"
)


def _inject_noninteractive(extra: List[str]) -> List[str]:
    """Append ``-noninteractive`` if the caller didn't already pass it."""
    if any(a in ("-noninteractive", "--noninteractive") for a in extra):
        return extra
    return extra + ["-noninteractive"]


def _parse_ffuf_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from ffuf's output.

    Returns a dict with:

    - ``findings``: list of ``{"path", "status", "size", "words", "lines",
      "duration"}`` dicts for every matched response ffuf reported.
    - ``findings_count``: integer count of matched responses.
    - ``meta``: the ``::`` header block (URL, method, threads, wordlist)
      parsed into a dict when present.

    Handles both ffuf's default human-readable table output (``[Status: ...,
    Size: ..., Words: ..., Lines: ...]: /path``) and ``-json`` newline-
    delimited JSON records (``{"url","status","length","words","lines",
      "input", ...}``).
    """
    findings: List[Dict[str, Any]] = []
    seen = set()
    meta: Dict[str, Any] = {}

    for line in log_text.splitlines():
        s = line.strip()
        # ffuf's banner/header lines look like " :: URL : http://..."
        if s.startswith("::"):
            kv = s.lstrip(":").strip()
            if ":" in kv:
                key, _, val = kv.partition(":")
                meta[key.strip()] = val.strip()
            continue

        # JSON record mode (-json).
        if s.startswith("{"):
            try:
                rec = _json.loads(s)
            except _json.JSONDecodeError:
                rec = None
            if isinstance(rec, dict) and ("status" in rec or "url" in rec):
                path = rec.get("input") or rec.get("url") or ""
                if isinstance(path, list):
                    path = "/".join(str(p) for p in path)
                key = (rec.get("status"), str(path))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "path": path,
                        "status": rec.get("status"),
                        "size": rec.get("length"),
                        "words": rec.get("words"),
                        "lines": rec.get("lines"),
                        "duration": rec.get("duration"),
                    }
                )
                continue

        m = _FFUF_ROW_RE.search(s)
        if m:
            status = int(m.group("status"))
            path = m.group("path")
            key = (status, path)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "path": path,
                    "status": status,
                    "size": int(m.group("size")),
                    "words": int(m.group("words")),
                    "lines": int(m.group("lines")),
                    "duration": m.group("duration"),
                }
            )

    return {
        "findings": findings,
        "findings_count": len(findings),
        "meta": meta,
    }


@framework_tool(
    "Launch and start a new ffuf web fuzzing run against a target URL: "
    "discovers hidden directories, files, vhosts, or parameters by "
    "brute-forcing a wordlist against the FUZZ keyword. Non-blocking and "
    "detached — starts the run in the background and returns immediately "
    "with a job ID for later retrieval.",
    next_hints=["ffuf_status"],
)
def run_ffuf(url: str, wordlist: str, options: str = "") -> Dict[str, Any]:
    """Launch ffuf against ``url`` and return immediately.

    ffuf runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the run.  Poll the result with
    ``ffuf_status(job_id)`` until it reports ``status: "done"``.

    ``-u`` is set to ``url`` and ``-w`` to ``wordlist``; the URL must
    contain the ``FUZZ`` keyword where the wordlist entries are substituted
    (e.g. ``http://10.0.0.1/FUZZ`` or ``http://10.0.0.1/?FUZZ=1``).
    ``-noninteractive`` is forced (appended if not already in ``options``)
    so ffuf never opens its interactive console on the detached subprocess.

    Args:
        url: The target URL containing the ``FUZZ`` keyword, e.g.
            ``http://10.0.0.1/FUZZ``.  Passed as its own argv element and
            never interpolated into a shell string.
        wordlist: Path to the wordlist file (passed to ``-w``).
        options: Additional ffuf command-line options as a single string
            (e.g. ``"-mc 200,301,401 -t 80 -recursion -recursion-depth 2"``).
            Quoted sub-phrases are preserved by shlex.  ``-noninteractive``
            is injected automatically if absent.
    """
    import shlex

    opt_list = shlex.split(options) if options else []
    opt_list = _inject_noninteractive(opt_list)

    # ``-u`` and ``-w`` are always explicit so the caller can't accidentally
    # omit the essentials; extra -w / -u in options are allowed by ffuf.
    command = ["ffuf", "-u", url, "-w", wordlist, *opt_list]

    return launch_job(
        command,
        tool_name="ffuf",
        timeout=float(__import__("os").getenv("FFUF_TIMEOUT", "1800")),
        verdict_parser=_parse_ffuf_verdict,
    )


@framework_tool(
    "Poll, check, or monitor the progress and results of an existing, "
    "already-launched ffuf fuzzing job: returns running/done, a parsed list "
    "of discovered paths with HTTP status / size / words / lines, run meta "
    "(URL, method, threads, wordlist), and recent log lines. Call until the "
    "job reports done.",
    next_hints=["ffuf_status", "report_finding"],
)
def ffuf_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a run launched by ``run_ffuf``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses ffuf's output for discovered paths/responses.  Returns
    ``status: "running"`` while the run is in progress and ``status:
    "done"`` once the process has exited.

    Args:
        job_id: The ``job_id`` returned by ``run_ffuf``.
    """
    return poll_job(job_id, tool_name="ffuf")


@framework_tool(
    "Cancel, stop, and terminate an existing, already-launched ffuf "
    "fuzzing job by its job ID: sends SIGTERM (then SIGKILL if needed) "
    "to the background subprocess and frees the job. Use this when a run is "
    "taking too long, is no longer needed, or was launched by mistake.",
    next_hints=["ffuf_status"],
)
def ffuf_cancel(job_id: str) -> Dict[str, Any]:
    """Terminate an ffuf run launched by ``run_ffuf``.

    Sends SIGTERM to the background subprocess (escalating to SIGKILL if it
    doesn't exit within a few seconds) and marks the job terminated.  The
    job's log file is preserved so any partial findings captured so far can
    still be read via ``ffuf_status(job_id)``.

    Args:
        job_id: The ``job_id`` returned by ``run_ffuf``.
    """
    terminated = terminate_job(job_id)
    return {
        "job_id": job_id,
        "tool": "ffuf",
        "cancelled": terminated,
        "message": (
            f"ffuf job {job_id} terminated"
            if terminated
            else f"no live ffuf job with id {job_id!r} (already finished or evicted)"
        ),
    }
