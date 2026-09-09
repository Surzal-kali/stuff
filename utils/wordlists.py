"""Shared wordlist discovery and launch-time preflight checks.

Both :mod:`payloads.ffuf` (path fuzzing) and :mod:`payloads.hydra` (credential
brute-force) consume wordlists under ``/usr/share/wordlists``.  Rather than
each tool re-implementing the lookup, this module owns:

- :data:`WORDLISTS_ROOT` — the root to walk (env-overridable).
- :func:`preflight_wordlists` — a launch-time sanity check called from
  ``bootstrap.FrameworkLoader.launch_all`` that confirms the wordlist tree
  exists and actually contains ``.txt`` files.  A missing or empty tree is
  the #1 cause of silent ffuf/hydra failures (ffuf exits with "could not
  read wordlist", hydra errors on ``-P``/``-L`` paths); surfacing this at
  launch time turns a runtime mystery into a startup warning.
- :func:`discover_wordlists` — a generator that walks the tree for files
  matching a glob, returning dicts with ``path``, ``size``, ``lines`` (best
  effort), and a category hint derived from the parent directory name.

The ``list_wordlists`` :func:`~payloads.wordlists.list_wordlists` tool wraps
:func:`discover_wordlists` for the secretary model so it can pick the right
wordlist path before calling ``run_ffuf`` / ``run_hydra``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

# Default Kali/Debian wordlist root.  Override with the WORDLISTS_ROOT env var
# (used by tests and non-standard installs).
WORDLISTS_ROOT: Path = Path(
    os.getenv("WORDLISTS_ROOT", "/usr/share/wordlists")
).resolve()

# Well-known wordlists that ffuf/hydra runs commonly target.  Used by the
# preflight to report which "headline" lists are present vs absent, so a
# missing rockyou.txt (gzip-only on Kali) is flagged explicitly rather than
# buried in a 6 000-entry count.
COMMON_WORDLISTS: Dict[str, str] = {
    "rockyou.txt": "SecLists/Passwords/Leaked-Databases/rockyou.txt",
    "dirb_common": "SecLists/Discovery/Web-Content/dirb/common.txt",
    "directory_list_2.3_small": "SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "raft_small_dirs": "SecLists/Discovery/Web-Content/raft-small-directories.txt",
    "names_top": "SecLists/Usernames/top-usernames-shortlist.txt",
}

# Short, pre-existing SecLists defaults used as "just in case" fallbacks when a
# caller omits the wordlist argument.  These are deliberately small so a
# forgotten argument runs a quick sane pass instead of failing (ffuf: "could
# not read wordlist") or erroring (hydra: no cred source).  Override via env:
#   DEFAULT_FFUF_WORDLIST / DEFAULT_HYDRA_LOGIN_LIST / DEFAULT_HYDRA_PASSWORD_LIST
DEFAULT_FFUF_WORDLIST: str = os.getenv(
    "DEFAULT_FFUF_WORDLIST",
    "SecLists/Discovery/Web-Content/common.txt",  # 4 751 lines; canonical ffuf quick default
)
DEFAULT_HYDRA_LOGIN_LIST: str = os.getenv(
    "DEFAULT_HYDRA_LOGIN_LIST",
    "SecLists/Usernames/top-usernames-shortlist.txt",  # 17 lines: root, admin, ...
)
DEFAULT_HYDRA_PASSWORD_LIST: str = os.getenv(
    "DEFAULT_HYDRA_PASSWORD_LIST",
    "SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt",  # 25 lines
)


def resolve_wordlist(rel_path: str, root: Optional[Path] = None) -> Optional[str]:
    """Resolve a wordlist path relative to :data:`WORDLISTS_ROOT`.

    Accepts either a relative SecLists path (e.g.
    ``SecLists/Discovery/Web-Content/common.txt``) or an absolute path that
    already exists.  Returns the absolute ``str`` path if the file exists,
    otherwise ``None`` — never raises, so callers can fall back to a clear
    error message that points at ``list_wordlists``.
    """
    base = (root or WORDLISTS_ROOT)
    # An existing absolute path is honoured as-is.
    p = Path(rel_path)
    if p.is_absolute() and p.is_file():
        return str(p)
    candidate = base / rel_path
    if candidate.is_file():
        return str(candidate)
    return None


def resolve_default_wordlist(kind: str, root: Optional[Path] = None) -> Optional[str]:
    """Resolve the framework default wordlist for ``kind``.

    ``kind`` is one of ``"ffuf"``, ``"hydra_logins"``, ``"hydra_passwords"``.
    Returns the absolute path string if the default file exists under the
    wordlist root, otherwise ``None``.
    """
    mapping = {
        "ffuf": DEFAULT_FFUF_WORDLIST,
        "hydra_logins": DEFAULT_HYDRA_LOGIN_LIST,
        "hydra_passwords": DEFAULT_HYDRA_PASSWORD_LIST,
    }
    rel = mapping.get(kind)
    if not rel:
        return None
    return resolve_wordlist(rel, root=root)


def _count_lines(path: Path) -> Optional[int]:
    """Best-effort line count; ``None`` if the file can't be read (binary/perm)."""
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except (OSError, ValueError):
        return None


def _category_from_path(path: Path, root: Path) -> str:
    """Derive a short category label from the path's first segment under root.

    e.g. ``SecLists/Passwords/Leaked-Databases/rockyou.txt`` -> ``Passwords``.
    Returns ``"wordlists"`` as a fallback.
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return "wordlists"
    parts = rel.parts
    # SecLists/<Category>/... -> Category; otherwise the first dir or root.
    if len(parts) >= 2 and parts[0] == "SecLists":
        return parts[1]
    return parts[0] if parts else "wordlists"


def discover_wordlists(
    root: Optional[Path] = None,
    pattern: str = "*.txt",
    include_hidden: bool = False,
) -> Iterator[Dict[str, Any]]:
    """Walk ``root`` (default :data:`WORDLISTS_ROOT`) yielding matching files.

    Yields a dict per file with ``path`` (absolute, ``str``), ``size`` (bytes),
    ``lines`` (best-effort, may be ``None``), and ``category`` (a short label).

    Skips ``.git`` and other VCS/junk directories so a cloned SecLists repo
    doesn't surface vendored metadata as wordlists.
    """
    base = (root or WORDLISTS_ROOT)
    if not base.exists():
        return
    skip_dirs = {".git", ".github", ".svn", "__pycache__", "node_modules", ".bin"}
    for path in sorted(base.rglob(pattern)):
        if not path.is_file():
            continue
        if not include_hidden and any(
            part.startswith(".") and part not in (".", "..") for part in path.relative_to(base).parts
        ):
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        yield {
            "path": str(path),
            "size": path.stat().st_size,
            "lines": _count_lines(path),
            "category": _category_from_path(path, base),
        }


def preflight_wordlists(root: Optional[Path] = None) -> Dict[str, Any]:
    """Launch-time sanity check for the wordlist tree.

    Returns a report dict:

    - ``ok`` (bool): True only when the root exists AND contains at least one
      ``.txt`` file.
    - ``root`` (str): the resolved root path checked.
    - ``txt_count`` (int): number of ``.txt`` files found.
    - ``common_present`` / ``common_absent`` (list[str]): which of
      :data:`COMMON_WORDLISTS` resolved to an existing file.
    - ``warnings`` (list[str]): human-readable problems.

    Idempotent and read-only — safe to call from ``launch_all``.
    """
    base = (root or WORDLISTS_ROOT)
    report: Dict[str, Any] = {
        "ok": False,
        "root": str(base),
        "txt_count": 0,
        "common_present": [],
        "common_absent": [],
        "warnings": [],
    }

    if not base.exists():
        report["warnings"].append(
            f"Wordlist root {base} does not exist; ffuf/hydra wordlist "
            "paths will fail. Install SecLists or set WORDLISTS_ROOT."
        )
        return report

    txt_files = list(discover_wordlists(base))
    report["txt_count"] = len(txt_files)
    if not txt_files:
        report["warnings"].append(
            f"No .txt wordlists found under {base}; ffuf/hydra runs have "
            "nothing to consume."
        )
        return report

    report["ok"] = True

    for name, rel in COMMON_WORDLISTS.items():
        candidate = base / rel
        if candidate.is_file():
            report["common_present"].append(name)
        else:
            report["common_absent"].append(name)

    # rockyou.txt is the single most-used password list; flag its absence
    # loudly because Kali ships it gzip-compressed and a decompression step
    # is a common tripping point.
    if "rockyou.txt" in report["common_absent"]:
        gz = base / "SecLists" / "Passwords" / "Leaked-Databases" / "rockyou.txt.gz"
        if gz.is_file():
            report["warnings"].append(
                f"rockyou.txt is absent but {gz.name} exists — gunzip it "
                "before pointing hydra -P / ffuf -w at it."
            )
    return report


__all__ = [
    "WORDLISTS_ROOT",
    "COMMON_WORDLISTS",
    "discover_wordlists",
    "preflight_wordlists",
]
