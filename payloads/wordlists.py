"""Wordlist discovery tool shared by ffuf and hydra.

``list_wordlists`` walks the framework's wordlist tree (default
``/usr/share/wordlists``) for ``.txt`` files and returns a compact catalog so
the secretary model can pick the right path before calling ``run_ffuf`` or
``run_hydra``.  Both tools consume wordlists verbatim as file paths, so a
wrong or non-existent path is the dominant silent-failure mode; this tool
turns "guess a path" into "search the catalog".

The ``next_hints`` point at both brute-force launchers so the manifest guides
the model from discovery straight to a run.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.wordlists import (
    WORDLISTS_ROOT,
    discover_wordlists,
    preflight_wordlists,
    resolve_default_wordlist,
)


def _category_matches(filter_str: str, category: str) -> bool:
    """True if *filter_str* matches the full category or any of its segments.

    Splits the multi-level category (e.g. ``Discovery/Web-Content``) on
    ``/`` so a filter like ``"web-content"`` matches even though it is only
    one segment of a deeper label.
    """
    cat_lower = category.lower()
    if filter_str in cat_lower:
        return True
    return any(filter_str in seg for seg in cat_lower.split("/"))


def _summarize(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """Per-category counts so the model sees the shape of the catalog."""
    counts: Dict[str, int] = {}
    for e in entries:
        counts[e.get("category", "wordlists")] = counts.get(
            e.get("category", "wordlists"), 0
        ) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


@framework_tool(
    "Discover and list available wordlist (.txt) files under the framework "
    "wordlist tree (default /usr/share/wordlists, e.g. SecLists). Returns a "
    "compact catalog grouped by category (Passwords, Discovery/Web-Content, "
    "Usernames, etc.) with each entry's absolute path, and size,— "
    "use the returned path verbatim as the -w argument to run_ffuf or the "
    "-P/-L argument to run_hydra. Optional category filter narrows the walk. "
    "Call this BEFORE run_ffuf/run_hydra to avoid guessing a wordlist path.",
    next_hints=["run_ffuf", "run_hydra"],
)
def list_wordlists(
    category: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """List ``.txt`` wordlists under :data:`~utils.wordlists.WORDLISTS_ROOT`.

    Walks the tree once (no caching) and returns up to ``limit`` entries so a
    full SecLists install (~6 000 files) doesn't blow the turn budget.  The
    ``by_category`` summary is always complete regardless of ``limit``.

    Args:
        category: Optional case-insensitive filter matched against the
            category label and any of its ``/``-separated segments (e.g.
            ``"Passwords"``, ``"web-content"``, or ``"Discovery"`` all match
            ``Discovery/Web-Content``).  ``None`` returns all categories.
        limit: Maximum number of entries to return (default 200).  The
            category summary is unaffected by this cap.
    """
    limit = max(0, min(int(limit), 2000))
    cat_filter = category.lower() if category else None

    # Run the preflight inline so a missing/empty tree is reported as a
    # structured warning rather than an empty list that looks like "no
    # match".  The model can then surface the install hint.
    pf = preflight_wordlists()

    entries: List[Dict[str, Any]] = []
    for e in discover_wordlists():
        if cat_filter and not _category_matches(cat_filter, e.get("category", "")):
            continue
        entries.append(e)

    by_category = _summarize(entries)
    total = len(entries)
    capped = entries[:limit] if limit else []

    return {
        "ok": pf["ok"],
        "root": pf["root"],
        "total": total,
        "returned": len(capped),
        "limit_applied": total > len(capped),
        "by_category": by_category,
        "wordlists": capped,
        "common_present": pf["common_present"],
        "common_absent": pf["common_absent"],
        "warnings": pf["warnings"],
        # The "just in case" fallback wordlists run_ffuf/run_hydra use when
        # no list is supplied.  A None value means the default file is absent
        # under the root — ffuf/hydra will error in that case.
        "defaults": {
            "ffuf": resolve_default_wordlist("ffuf"),
            "hydra_logins": resolve_default_wordlist("hydra_logins"),
            "hydra_passwords": resolve_default_wordlist("hydra_passwords"),
        },
    }
