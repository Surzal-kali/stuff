"""Nmap port scanner with background job + poll pattern.

nmap scans (especially ``-p- -sV``) can take minutes to tens of minutes.
A blocking ``subprocess.run`` holds the entire secretary turn open for the
scan's full runtime and fights the turn timeout.  Instead, this module uses
the shared :mod:`utils.background_job` helper:

- ``run_nmap(target, options)`` launches nmap as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id`` plus a log
  file path.  The secretary turn is NOT held open.
- ``nmap_status(job_id)`` polls the job: checks whether the process is
  still alive, tails the log, and parses a summary of open ports so the
  model can decide whether to keep polling or proceed to the next tool.

This mirrors the proven sqlmap ``run_sqlmap`` / ``sqlmap_status`` shape
and inherits the shared ``BackgroundJob`` machinery so amass/gobuster can
do the same with a one-line ``launch_job`` call.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from constants import framework_tool
from utils.background_job import launch_job, poll_job


def _parse_nmap_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from nmap's text output.

    Returns a dict with ``open_ports`` (list of ``"port/state/service"``
    strings) and ``host_state`` (``"up"`` / ``"down"`` / ``None``).
    Conservative: only extracts lines that match nmap's standard
    ``Nmap scan report for ...`` and ``<port>/<state> <service>`` formats.
    """
    host_state = None
    m = re.search(r"Host is (up|down)", log_text, re.IGNORECASE)
    if m:
        host_state = m.group(1).lower()
    elif re.search(r"Nmap scan report for .+ is (up|down)", log_text, re.IGNORECASE):
        host_state = m.group(1).lower() if m else None

    open_ports: List[str] = []
    # Match lines like: 22/tcp   open  ssh
    #                 80/tcp   open  http
    for line in log_text.splitlines():
        pm = re.match(
            r"^(\d+/(?:tcp|udp))\s+(\w+)\s+(\S+)", line.strip()
        )
        if pm:
            port, state, service = pm.groups()
            open_ports.append(f"{port}/{state}/{service}")

    return {
        "open_ports": open_ports,
        "host_state": host_state,
    }


@framework_tool(
    "Launch an Nmap port scan on a target in the background; returns a "
    "job_id you poll with nmap_status. The scan runs detached and writes "
    "to a log file — this call does NOT block.",
    next_hints=["nmap_status"],
)
def run_nmap(target: str, options: str = "-Pn -sV") -> Dict[str, Any]:
    """Launch nmap against ``target`` and return immediately.

    nmap runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan.  Poll the result with
    ``nmap_status(job_id)`` until it reports ``status: "done"``.

    ``-Pn`` is the default (hosts that drop ping probes would otherwise
    report "Host seems down" even when their ports are reachable).  Pass
    ``-p-`` for all ports, ``-sV`` for service detection, ``-O`` for OS
    fingerprinting, etc.

    Args:
        target: The target host or IP address (or CIDR range).
        options: Additional nmap command-line options as a single string
            (e.g. ``"-p- -sV -sC"``).  Quoted sub-phrases are preserved by
            shlex.  ``-Pn`` is included by default.
    """
    import shlex

    # -Pn by default: hosts that drop ping probes would otherwise report
    # "Host seems down" even when their ports are reachable.
    opt_list = shlex.split(options) if options else []
    if "-Pn" not in opt_list and "-Pn" not in options:
        opt_list = ["-Pn", *opt_list]

    command = ["nmap", *opt_list, target]

    return launch_job(
        command,
        tool_name="nmap",
        timeout=float(__import__("os").getenv("NMAP_TIMEOUT", "1800")),
        verdict_parser=_parse_nmap_verdict,
    )


@framework_tool(
    "Poll an Nmap scan job: returns running/done, a parsed list of open "
    "ports with services, the host up/down verdict, and recent log lines. "
    "Call until the scan reports done.",
    next_hints=["nmap_status", "report_finding"],
)
def nmap_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a scan launched by ``run_nmap``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses nmap's output for open ports.  Returns ``status: "running"``
    while the scan is in progress and ``status: "done"`` once the process
    has exited.

    Args:
        job_id: The ``job_id`` returned by ``run_nmap``.
    """
    return poll_job(job_id, tool_name="nmap")