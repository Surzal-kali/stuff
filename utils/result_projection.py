"""Result projection: control what enters model context vs. what stays in scratch.

The projection layer sits between ``execute_tool()`` and the result entering
the model's conversation history.  It operates in three modes:

    full    — zero behavior change; the raw result passes through unchanged.
    digest  — store the full result in scratch, return a compact per-tool-family
              digest + the scratch reference + the retrieval instruction.
    page    — store the full result in scratch, return a bounded page of the
              result (offset/limit) + the scratch reference + continuation info.

The ``result_mode`` is an execution-envelope parameter — it is NOT a tool
argument and never reaches the tool body.  The gateway and the secretary
agent pass it alongside ``tool_id`` / ``arguments``.

Digest adapter registration
---------------------------
Tools that want a family-specific digest register a ``to_digest(raw_result)``
callable via ``@framework_tool(..., result_digest=my_digest)``.  The adapter
returns ``{"summary": str, "row_hint_format": str}`` — the projection layer
wraps it in the standard envelope.  Tools without an adapter fall back to a
naive head+count digest (a bounded preview, not a "real" digest).

Why this is NOT the parked OWUI trim filter:
    - The projection runs BEFORE the result enters context, not after.
    - The retrieval instruction is part of the return — the model is taught
      the move every call, never left guessing how to get the full output.
    - Per-tool-family digest logic is honest because the tool knows its own
      output structure; a generic post-hoc summarizer does not.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Dict, Optional

from utils.scratch_store import ScratchStore, get_store

logger = logging.getLogger(__name__)

# --- Small-result passthrough threshold ------------------------------------
# Results whose serialized JSON is under this many bytes are returned in full
# regardless of result_mode.  Small results (ssh_connect returns a handle,
# check_scope returns a verdict, report_finding returns an ID) were never a
# context problem — storing them in scratch is wasted I/O and an extra
# retrieval round-trip for the model.  Only large outputs (nmap logs, ffuf
# hit lists, grep match dumps) trigger the digest/page projection.
_SMALL_RESULT_THRESHOLD = int(os.getenv("SCRATCH_SMALL_RESULT_BYTES", "2048"))


# --- Digest adapter registry -----------------------------------------------
#
# Maps tool_id -> to_digest callable.  Populated at decoration time via
# @framework_tool(..., result_digest=fn) and at registry build time from the
# manifest's result_digest field.  The registry's dynamic-discovery pass sets
# func._result_digest which the manifest carries; this module looks it up
# by tool_id at projection time.
#
# Adapters are also registered directly here for tools that set
# result_digest in the decorator (the common path).

_DIGEST_ADAPTERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}


def register_digest_adapter(
    tool_id: str, adapter: Callable[[Dict[str, Any]], Dict[str, Any]]
) -> None:
    """Register a per-tool digest adapter.

    The adapter takes the raw tool result dict and returns a dict with:
        - ``summary``: a compact, structurally-honest digest string.
        - ``row_hint_format`` (optional): a format hint for filtered retrieval,
          e.g. ``"scratch_search scratch:<id> --filter 'port:8080'"``.
    """
    _DIGEST_ADAPTERS[tool_id] = adapter


def get_digest_adapter(tool_id: str) -> Optional[Callable]:
    """Look up a registered digest adapter for a tool_id."""
    return _DIGEST_ADAPTERS.get(tool_id)


# --- Projection envelope shapes --------------------------------------------

_DIGEST_TEMPLATE = {
    "mode": "digest",
    "summary": "",         # filled by adapter or naive fallback
    "full_ref": "",        # scratch:<id>
    "retrieval": "",       # how to pull the full output
    "row_hint": "",        # how to pull specific rows (optional)
}

_PAGE_TEMPLATE = {
    "mode": "page",
    "summary": "",         # e.g. "Showing 50 of 312 rows"
    "rows": [],            # the bounded page
    "full_ref": "",
    "next": "",            # how to get the next page
}


# --- Public projection API --------------------------------------------------

def project_result(
    result: Dict[str, Any],
    *,
    result_mode: str = "full",
    tool_id: str = "",
    agent_id: str = "0",
    chat_id: Optional[str] = None,
    page_offset: int = 0,
    page_limit: int = 50,
) -> Dict[str, Any]:
    """Apply a result projection based on ``result_mode``.

    This is the single entry point called by the gateway, MCP handler, and
    the secretary agent after ``execute_tool()`` returns.

    Args:
        result: The raw tool result dict from execute_tool().
        result_mode: ``"full"``, ``"digest"``, or ``"page"``.
        tool_id: The tool that produced this result (for adapter lookup).
        agent_id: The agent/session owning this result (for scratch ownership).
        chat_id: Optional chat id for scratch ownership.
        page_offset: Page offset (``page`` mode only).
        page_limit: Page size cap (``page`` mode only).

    Returns:
        - ``full`` mode: the raw result, unchanged.
        - ``digest`` mode: a digest envelope with a scratch reference.
        - ``page`` mode: a bounded page envelope with a scratch reference.
    """
    mode = (result_mode or "full").strip().lower()

    if mode == "full" or not isinstance(result, dict):
        return result

    # Unwrap the executor transport envelope before projecting.
    #
    # The in-process/BRAIN_DISPATCH executor wraps every tool result as
    # ``{"stdout": <json str>, "status": "Success"|"Failed", "result": <raw>}``
    # (see daharness/executor.py:_wrap_launch_result).  Without unwrapping,
    # the digest/page adapters run on the *envelope*, not the tool result:
    # e.g. nmap_status's adapter read ``status="Success"`` (the envelope's
    # transport status) and ``open_ports=[]`` (nested under ``result``, not
    # at top level), so the digest reported 0 open ports while the scratch
    # copy held the real 2.  The stored scratch payload and the envelope the
    # model sees must both carry the tool's own fields.
    envelope_status = ""
    if "result" in result and "stdout" in result and "status" in result:
        envelope_status = str(result.get("status", "")).lower()
        result = result["result"]
        if not isinstance(result, dict):
            return result

    # Failed results are always returned in full — a digest of an error
    # loses the error text the model needs to self-correct.  This covers
    # both the unwrapped tool result's own status (e.g. poll_job returning
    # status="done" — never failed/error, so never short-circuited here)
    # and the executor envelope's transport status (Failed).
    status = envelope_status or str(result.get("status", "")).lower()
    if status in ("failed", "error"):
        return result

    # Small-result passthrough: if the serialized result is under the
    # threshold, return it in full regardless of result_mode.  Small results
    # (handles, verdicts, IDs, config probes) were never a context problem —
    # storing them in scratch is wasted I/O and a retrieval round-trip.
    try:
        result_size = len(json.dumps(result, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        result_size = 0
    if result_size <= _SMALL_RESULT_THRESHOLD:
        return result

    store = get_store()

    # Store the full result in scratch.
    try:
        scratch_info = store.store(
            result,
            agent_id=agent_id,
            tool_id=tool_id,
            chat_id=chat_id,
        )
    except Exception as exc:
        logger.warning(f"[projection] scratch store failed for {tool_id}: {exc}")
        # Storage failed — return the full result so the model isn't left
        # with nothing.  This is a graceful degradation, not a silent loss.
        result["_projection_note"] = (
            f"scratch store unavailable ({exc}); returning full result"
        )
        return result

    scratch_ref = scratch_info["scratch_ref"]

    if mode == "digest":
        return _build_digest(result, tool_id, scratch_ref, scratch_info)
    elif mode == "page":
        return _build_page(
            result, tool_id, scratch_ref, scratch_info,
            offset=page_offset, limit=page_limit,
        )
    else:
        # Unknown mode — degrade to full.
        logger.warning(f"[projection] unknown result_mode {result_mode!r}; returning full")
        return result


# --- Digest builder --------------------------------------------------------

def _build_digest(
    result: Dict[str, Any],
    tool_id: str,
    scratch_ref: str,
    scratch_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a digest envelope using a registered adapter or the naive fallback."""
    adapter = get_digest_adapter(tool_id)

    if adapter is not None:
        try:
            digest = adapter(result)
            summary = digest.get("summary", "")
            row_hint = digest.get("row_hint_format", "")
        except Exception as exc:
            logger.warning(f"[projection] digest adapter for {tool_id} failed: {exc}")
            summary, row_hint = _naive_digest(result, scratch_ref)
    else:
        summary, row_hint = _naive_digest(result, scratch_ref)

    retrieval = (
        f"Call framework_scratch_search with scratch_ref='{scratch_ref}' "
        f"to retrieve the full output."
    )

    envelope = dict(_DIGEST_TEMPLATE)
    envelope["summary"] = summary
    envelope["full_ref"] = scratch_ref
    envelope["retrieval"] = retrieval
    if row_hint:
        envelope["row_hint"] = row_hint
    envelope["tool_id"] = tool_id
    envelope["stored_bytes"] = scratch_info.get("stored_bytes", 0)
    return envelope


# --- Page builder ----------------------------------------------------------

def _build_page(
    result: Dict[str, Any],
    tool_id: str,
    scratch_ref: str,
    scratch_info: Dict[str, Any],
    *,
    offset: int,
    limit: int,
) -> Dict[str, Any]:
    """Build a bounded page envelope from the result's list-bearing fields."""
    # Find the primary list field to page.  Priority: rows, open_ports,
    # recent_lines, results, candidates, all, items, findings.  Fallback:
    # the first list value found.
    list_fields_priority = (
        "rows", "open_ports", "recent_lines", "results",
        "candidates", "all", "items", "findings", "matches",
    )

    paged_field = None
    paged_value: list = []

    for field in list_fields_priority:
        val = result.get(field)
        if isinstance(val, list) and val:
            paged_field = field
            paged_value = val
            break

    if paged_field is None:
        # No list field found — page the whole result as a single item.
        total = 1
        page_items = [result] if offset == 0 else []
        summary = f"Showing {'1' if offset == 0 else '0'} of 1 (non-list result)"
    else:
        total = len(paged_value)
        page_slice = paged_value[offset:offset + limit] if limit > 0 else paged_value[offset:]
        page_items = page_slice
        shown = len(page_slice)
        summary = f"Showing {shown} of {total} {paged_field}"

    envelope = dict(_PAGE_TEMPLATE)
    envelope["summary"] = summary
    envelope["rows"] = page_items
    envelope["paged_field"] = paged_field or "(full result)"
    envelope["full_ref"] = scratch_ref
    envelope["total"] = total
    envelope["offset"] = offset
    envelope["limit"] = limit
    envelope["tool_id"] = tool_id

    # Continuation: how to get the next page.
    next_offset = offset + limit if limit > 0 and offset + limit < total else None
    if next_offset is not None:
        envelope["next"] = (
            f"Call framework_scratch_search with scratch_ref='{scratch_ref}' "
            f"offset={next_offset} limit={limit} to get the next page."
        )
    else:
        envelope["next"] = (
            f"End of results. Full output available at {scratch_ref}."
        )

    return envelope


# --- Naive fallback digest --------------------------------------------------

def _naive_digest(result: Dict[str, Any], scratch_ref: str) -> tuple:
    """Build a conservative fallback digest when no adapter is registered.

    This is a bounded preview, not a real digest.  It reports:
    - status
    - key names present
    - counts of any list fields
    - first ~500 chars of any string fields that look like output (stdout, note, summary)
    - the retrieval instruction

    Returns (summary_str, row_hint_str).
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    # Count list fields.
    for key, val in result.items():
        if isinstance(val, list) and val:
            parts.append(f"{key}={len(val)} items")
        elif isinstance(val, dict):
            parts.append(f"{key}={len(val)} keys")

    # Pull short text fields that help the model decide if it needs the full output.
    for key in ("summary", "note", "error", "job_id", "handle", "target"):
        val = result.get(key)
        if val is not None:
            text = str(val)
            if len(text) <= 200:
                parts.append(f"{key}={text}")
            else:
                parts.append(f"{key}={text[:200]}...")

    # Any stdout-like field gets a head preview.
    for key in ("stdout", "output", "raw", "recent_lines"):
        val = result.get(key)
        if isinstance(val, str) and val:
            preview = val[:500]
            parts.append(f"{key}_head={preview!r}")
        elif isinstance(val, list) and val:
            first = str(val[0])[:200] if val else ""
            parts.append(f"{key}[0]={first!r}")

    summary = " | ".join(parts)

    row_hint = (
        f"scratch_search {scratch_ref} --filter '<keyword>' "
        f"# pull specific rows from the full output"
    )

    return summary, row_hint