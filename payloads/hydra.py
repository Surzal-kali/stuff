"""Hydra credential brute-forcer with background job + poll pattern.

Hydra password-spray / brute-force runs can take minutes to tens of minutes
depending on the service, the size of the credential lists, and the per-host
throttling.  A blocking ``subprocess.run`` holds the entire secretary turn
open for the run's full runtime and fights the turn timeout.  Instead, this
module uses the shared :mod:`utils.background_job` helper:

- ``run_hydra(target, options)`` launches hydra as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id`` plus a log
  file path.  The secretary turn is NOT held open.
- ``hydra_status(job_id)`` polls the job: checks whether the process is
  still alive, tails the log, and parses a summary of any cracked
  credentials and the attempt progress so the model can decide whether to
  keep polling or proceed to the next tool.

This mirrors the proven nmap ``run_nmap`` / ``nmap_status`` shape and
inherits the shared ``BackgroundJob`` machinery.

Non-interactivity is enforced defensively: hydra is non-interactive by
default, but ``-f`` (stop on first valid pair) is *not* forced — the caller
chooses.  ``stdin`` is ``/dev/null`` via the shared launcher so any stray
prompt reads EOF instead of blocking.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job
from utils.wordlists import resolve_default_wordlist


# hydra's success line looks like:
#   host: 10.0.0.1   login: admin   password: letmein
# IPv4, IPv6 (in brackets), or a hostname may appear as the host value.
_HYDRA_FOUND_RE = re.compile(
    r"^host:\s+(?P<host>\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|[^\s:]+)\s+"
    r"login:\s+(?P<login>\S+)\s+"
    r"password:\s+(?P<password>.+?)\s*$",
    re.IGNORECASE,
)
_HYDRA_ATTEMPT_RE = re.compile(
    r"\[ATTEMPT\].*?\b(?P<n>\d+)\s+of\s+(?P<total>\d+)\b"
)
_HYDRA_SUMMARY_RE = re.compile(
    r"(?P<found>\d+)\s+(?:valid passwords? found|of \d+ target.*successfully completed)",
    re.IGNORECASE,
)


def _parse_hydra_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from hydra's text output.

    Returns a dict with:

    - ``credentials``: list of ``{"host", "login", "password"}`` dicts for
      every cracked pair hydra reported.
    - ``attempts``: ``{"done", "total"}`` progress from ``[ATTEMPT]`` lines
      (last seen values).
    - ``credentials_found``: integer count of cracked pairs.
    - ``status_line``: hydra's final summary line, if present.

    Conservative: only matches hydra's standard ``host: ... login: ...
    password: ...`` found-format and ``[ATTEMPT] ... N of M`` progress lines.
    """
    credentials: List[Dict[str, str]] = []
    seen_pairs = set()
    for line in log_text.splitlines():
        m = _HYDRA_FOUND_RE.match(line.strip())
        if m:
            key = (m.group("host"), m.group("login"), m.group("password"))
            if key not in seen_pairs:
                seen_pairs.add(key)
                credentials.append(
                    {
                        "host": m.group("host"),
                        "login": m.group("login"),
                        "password": m.group("password"),
                    }
                )

    attempts: Dict[str, Any] = {"done": None, "total": None}
    for line in log_text.splitlines():
        am = _HYDRA_ATTEMPT_RE.search(line)
        if am:
            attempts = {"done": int(am.group("n")), "total": int(am.group("total"))}

    status_line = None
    for line in reversed(log_text.splitlines()):
        s = line.strip()
        if s and ("successfully completed" in s.lower() or "valid password" in s.lower()):
            status_line = s
            break

    return {
        "credentials": credentials,
        "credentials_found": len(credentials),
        "attempts": attempts,
        "status_line": status_line,
    }


_HYDRA_CRED_FLAGS = {"-l", "-L", "-p", "-P", "-C", "-x"}


def _has_credential_source(opt_list: List[str]) -> bool:
    """True if ``options`` already names a hydra credential source.

    hydra needs at least one of ``-l``/``-L`` (login), ``-p``/``-P``
    (password), ``-C`` (colon file), or ``-x`` (module password generator).
    Without any of these hydra exits with an error before touching the
    target — the classic "forgot the wordlist" failure.
    """
    for tok in opt_list:
        if tok in _HYDRA_CRED_FLAGS:
            return True
        # glued short form, e.g. -Cfile or -Llogins
        if len(tok) > 2 and tok[:2] in _HYDRA_CRED_FLAGS:
            return True
    return False


def _inject_default_credentials(opt_list: List[str]) -> tuple[List[str], Dict[str, Any]]:
    """Inject default login + password lists when no cred source is set.

    Returns the (possibly extended) argv list and a meta dict describing
    what was injected, so ``run_hydra`` can surface it to the caller.  If
    the default files are absent, returns the list unchanged with an
    ``error`` key so ``run_hydra`` can fail loudly with a pointer to
    ``list_wordlists`` instead of letting hydra produce a cryptic message.
    """
    meta: Dict[str, Any] = {"default_creds_used": False}
    if _has_credential_source(opt_list):
        return opt_list, meta

    logins = resolve_default_wordlist("hydra_logins")
    passwords = resolve_default_wordlist("hydra_passwords")
    if not logins or not passwords:
        meta["error"] = (
            "No credential source (-l/-L/-p/-P/-C/-x) supplied and one or both "
            "framework defaults (DEFAULT_HYDRA_LOGIN_LIST / "
            "DEFAULT_HYDRA_PASSWORD_LIST) are missing under "
            "/usr/share/wordlists. Call list_wordlists to discover available "
            "lists, then pass -L <logins> -P <passwords>."
        )
        return opt_list, meta

    injected = list(opt_list) + ["-L", logins, "-P", passwords]
    meta["default_creds_used"] = True
    meta["default_login_list"] = logins
    meta["default_password_list"] = passwords
    return injected, meta


@framework_tool(
    "Launch and start a new Hydra credential brute-force / password-spray "
    "against a service target (e.g. ssh://10.0.0.1, ftp://host, "
    "http-post-form://host/path:user=^USER^&pass=^PASS^:F=invalid). "
    "Non-blocking and detached — starts the run in the background and "
    "returns immediately with a job ID for later retrieval.",
    next_hints=["hydra_status"],
)
def run_hydra(target: str, options: str = "") -> Dict[str, Any]:
    """Launch hydra against ``target`` and return immediately.

    Hydra runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the run.  Poll the result with
    ``hydra_status(job_id)`` until it reports ``status: "done"``.

    The ``target`` is hydra's ``service://server[:port][/OPT]`` operand
    (e.g. ``ssh://10.0.0.1:22``, ``ftp://192.168.0.5``, or for HTTP forms
    ``http-post-form://host/login.php:user=^USER^&pass=^PASS^:F=invalid``).
    Credentials and tuning come from ``options`` (``-l``/``-L`` for logins,
    ``-p``/``-P`` for passwords, ``-C`` for a colon file, ``-t`` for
    parallel tasks, ``-f`` to stop on first hit, ``-V`` for verbose
    per-attempt progress).

    Args:
        target: The hydra service target, e.g. ``ssh://10.0.0.1``.  This is
            passed as its own argv element and never interpolated into a
            shell string.
        options: Additional hydra command-line options as a single string
            (e.g. ``"-l admin -P /usr/share/wordlists/rockyou.txt -f -V"``).
            Quoted sub-phrases are preserved by shlex.  If no credential
            source (``-l``/``-L``/``-p``/``-P``/``-C``/``-x``) is present,
            short pre-existing SecLists defaults
            (``top-usernames-shortlist.txt`` + ``top-passwords-shortlist.txt``;
            overridable via ``DEFAULT_HYDRA_LOGIN_LIST`` /
            ``DEFAULT_HYDRA_PASSWORD_LIST``) are injected as a "just in case"
            fallback so a forgotten cred source runs a quick sane pass instead
            of erroring.  Call ``list_wordlists`` for a targeted run.
    """
    import shlex

    opt_list = shlex.split(options) if options else []
    opt_list, creds_meta = _inject_default_credentials(opt_list)
    if "error" in creds_meta:
        return {
            "job_id": None,
            "tool": "hydra",
            "status": "error",
            "error": creds_meta["error"],
        }

    command = ["hydra", *opt_list, target]

    job = launch_job(
        command,
        tool_name="hydra",
        timeout=float(__import__("os").getenv("HYDRA_TIMEOUT", "1800")),
        verdict_parser=_parse_hydra_verdict,
    )
    # Surface whether default cred lists were injected so the secretary
    # model knows to swap in targeted lists for a real run.
    job.update(creds_meta)
    return job


@framework_tool(
    "Poll, check, or monitor the progress and results of an existing, "
    "already-launched Hydra brute-force job: returns running/done, a parsed "
    "list of cracked credentials (host/login/password), attempt progress "
    "(N of M), and recent log lines. Call until the job reports done.",
    next_hints=["hydra_status", "report_finding"],
)
def hydra_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a run launched by ``run_hydra``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses hydra's output for cracked credentials and attempt progress.
    Returns ``status: "running"`` while the run is in progress and
    ``status: "done"`` once the process has exited.

    Args:
        job_id: The ``job_id`` returned by ``run_hydra``.
    """
    return poll_job(job_id, tool_name="hydra")


@framework_tool(
    "Cancel, stop, and terminate an existing, already-launched Hydra "
    "brute-force job by its job ID: sends SIGTERM (then SIGKILL if needed) "
    "to the background subprocess and frees the job. Use this when a run is "
    "taking too long, is no longer needed, or was launched by mistake.",
    next_hints=["hydra_status"],
)
def hydra_cancel(job_id: str) -> Dict[str, Any]:
    """Terminate a Hydra run launched by ``run_hydra``.

    Sends SIGTERM to the background subprocess (escalating to SIGKILL if it
    doesn't exit within a few seconds) and marks the job terminated.  The
    job's log file is preserved so any partial results captured so far can
    still be read via ``hydra_status(job_id)``.

    Args:
        job_id: The ``job_id`` returned by ``run_hydra``.
    """
    terminated = terminate_job(job_id)
    return {
        "job_id": job_id,
        "tool": "hydra",
        "cancelled": terminated,
        "message": (
            f"hydra job {job_id} terminated"
            if terminated
            else f"no live hydra job with id {job_id!r} (already finished or evicted)"
        ),
    }
