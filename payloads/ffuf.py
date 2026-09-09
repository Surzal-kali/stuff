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
import os
import re
import subprocess
import uuid
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Real ffuf table rows print the path BEFORE the bracket block:
#   admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]
# (verified against ffuf 1.1.0 on Debian Trixie; the "[Status: ...]: /path"
# format ffuf does not emit would silently never match).
_FFUF_ROW_RE = re.compile(
    r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*"
    r"Size:\s*(?P<size>\d+),\s*"
    r"Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
    r"(?:,\s*Duration:\s*(?P<duration>[\d.]+s))?\]"
)

# -noninteractive first appears in ffuf 2.0.0; Debian Trixie ships 1.1.0
# where the flag is fatal ("flag provided but not defined", exit 2).
_FFUF_NONINTERACTIVE_MIN = (2, 0)
_noninteractive_supported: Optional[bool] = None


def _ffuf_supports_noninteractive() -> bool:
    """Check (once) whether the installed ffuf knows -noninteractive."""
    global _noninteractive_supported
    if _noninteractive_supported is None:
        supported = False  # conservative default: don't inject
        try:
            out = subprocess.run(
                ["ffuf", "-V"], capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r"v?(\d+)\.(\d+)", out)
            if m:
                ver = (int(m.group(1)), int(m.group(2)))
                supported = ver >= _FFUF_NONINTERACTIVE_MIN
        except Exception:
            supported = False
        _noninteractive_supported = supported
    return _noninteractive_supported


def _inject_noninteractive(extra: List[str]) -> List[str]:
    """Append ``-noninteractive`` when the installed ffuf supports it.

    The detached launcher already sets stdin=/dev/null, which keeps ffuf
    non-interactive on versions without the flag (e.g. Trixie's 1.1.0).
    """
    if any(a in ("-noninteractive", "--noninteractive") for a in extra):
        return extra
    if _ffuf_supports_noninteractive():
        return extra + ["-noninteractive"]
    return extra


def _path_from_record(rec: Dict[str, Any]) -> str:
    """Extract the fuzzed value from a ffuf result record.

    JSON records carry it in ``input`` — a dict like ``{"FUZZ": "admin"}``
    in ffuf 1.x/2.x, or a list for multi-keyword runs; fall back to URL.
    """
    raw = rec.get("input")
    if isinstance(raw, dict) and raw:
        return str(next(iter(raw.values())))
    if isinstance(raw, list) and raw:
        return "/".join(str(p) for p in raw)
    return str(rec.get("url", ""))


def _parse_ffuf_output_file(out_path: str) -> Optional[Dict[str, Any]]:
    """Parse ffuf's ``-of json -o <file>`` output (one JSON object per file).

    Real file shape (ffuf 1.1.0, captured live): ``{"commandline": ...,
    "time": ..., "results": [{"input": {...}, "status": ..., "length":
    ..., ...}]}`` — results at a top-level ``"results"`` key.
    """
    try:
        with open(out_path, "r") as fh:
            data = _json.load(fh)
    except (OSError, ValueError):
        return None
    results = data.get("results")
    if not isinstance(results, list):
        return None
    findings = []
    for rec in results:
        if not isinstance(rec, dict):
            continue
        findings.append(
            {
                "path": _path_from_record(rec),
                "status": rec.get("status"),
                "size": rec.get("length"),
                "words": rec.get("words"),
                "lines": rec.get("lines"),
                "redirect": rec.get("redirectlocation"),
                "url": rec.get("url"),
                "duration": rec.get("duration"),
            }
        )
    return {
        "findings": findings,
        "findings_count": len(findings),
        "meta": {"source": "json"},
    }


def _parse_ffuf_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from ffuf's stdout (human table mode).

    Strips the ANSI ``\x1b[2K`` prefixes ffuf writes into redirected
    output, then parses path-first result rows.  Also accepts NDJSON
    records on stdout (some ffuf builds/modes emit those).  The
    ``-of json -o <file>`` output is parsed separately by
    ``_parse_ffuf_output_file`` and preferred by ``run_ffuf``'s verdict.
    """
    findings: List[Dict[str, Any]] = []
    seen = set()
    meta: Dict[str, Any] = {}

    for raw_line in log_text.splitlines():
        s = _ANSI_RE.sub("", raw_line).strip()
        if s.startswith("::"):
            kv = s.lstrip(":").strip()
            if ":" in kv:
                key, _, val = kv.partition(":")
                meta[key.strip()] = val.strip()
            continue

        if s.startswith("{"):
            try:
                rec = _json.loads(s)
            except _json.JSONDecodeError:
                rec = None
            if isinstance(rec, dict) and ("status" in rec or "url" in rec):
                path = _path_from_record(rec)
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
    (e.g. ``http://10.0.0.1/FUZZ``).  ``-of json -o <per-job file>`` is
    injected AFTER any caller options (last ``-o`` wins) so machine-
    readable results are always captured; ``ffuf_status`` prefers that
    file's findings over the human-table parse when both exist.

    Args:
        url: The target URL containing the ``FUZZ`` keyword, e.g.
            ``http://10.0.0.1/FUZZ``.  Passed as its own argv element and
            never interpolated into a shell string.
        wordlist: Path to the wordlist file (passed to ``-w``).
        options: Additional ffuf command-line options as a single string
            (e.g. ``"-mc 200,301,401 -t 80 -recursion -recursion-depth 2"``).
            Quoted sub-phrases are preserved by shlex.  ``-noninteractive``
            is injected only if the installed ffuf supports it (>= 2.0).
    """
    import shlex

    out_path = os.path.join(
        os.getenv("BG_JOB_LOG_DIR", "/tmp"), f"ffuf_out_{uuid.uuid4().hex[:8]}.json"
    )

    opt_list = shlex.split(options) if options else []
    opt_list = _inject_noninteractive(opt_list)

    # ``-u`` and ``-w`` are always explicit so the caller can't accidentally
    # omit the essentials; extra -w / -u in options are allowed by ffuf.
    # ``-of json -o`` goes LAST so it wins over any caller-provided -o.
    command = [
        "ffuf", "-u", url, "-w", wordlist,
        *opt_list, "-of", "json", "-o", out_path,
    ]

    def _verdict(log_text: str) -> Dict[str, Any]:
        verdict = _parse_ffuf_verdict(log_text)
        file_verdict = _parse_ffuf_output_file(out_path)
        if file_verdict and file_verdict.get("findings_count"):
            verdict["findings"] = file_verdict["findings"]
            verdict["findings_count"] = file_verdict["findings_count"]
            verdict["meta"]["output_file"] = out_path
        return verdict

    return launch_job(
        command,
        tool_name="ffuf",
        timeout=float(os.getenv("FFUF_TIMEOUT", "1800")),
        verdict_parser=_verdict,
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
