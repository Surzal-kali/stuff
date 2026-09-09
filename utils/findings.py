"""Framework tools for reporting and reviewing security findings.

``report_finding`` is the terminal action for any tool chain — it mints a
structured :class:`daharness.models.Finding` in the SQLite findings store and
stores a lightweight one-line pointer in vector memory so the secretary can
recall that the finding *exists* later without bloating its context with the
full evidence payload.

``render_findings`` reads the findings store and returns a markdown report
suitable as a bug-bounty submission draft or lab documentation.  The secretary
can call it mid-session to review what has been found so far.
"""

from __future__ import annotations

import time
from uuid import uuid4
from typing import Dict, List, Optional

from constants import framework_tool
from daharness.findings import FindingStore
from utils.memory_tools import remember_text


@framework_tool(
    "Report a structured security finding. This is the TERMINAL action for "
    "any tool chain — call it after you have gathered evidence. Provide a "
    "title, severity (P1 critical / P2 high / P3 medium / P4 info), the asset "
    "affected, and any evidence (request, response, excerpt), reproduction "
    "steps, and the list of tools used in this chain. The finding is stored "
    "persistently and a short pointer is saved to memory so it can be "
    "recalled later. Returns a brief confirmation with the finding ID.",
    next_hints=["render_findings"],
)
def report_finding(
    title: str,
    severity: str,
    asset: str,
    cwe: str = "",
    evidence_request: str = "",
    evidence_response: str = "",
    evidence_excerpt: str = "",
    repro: str = "",
    tool_chain: str = "",
) -> str:
    """Report a finding to the findings store.

    Args:
        title: Short summary, e.g. "SQL Injection in /login".
        severity: P1 (critical), P2 (high), P3 (medium), P4 (info).
        asset: The affected host/URL/endpoint.
        cwe: CWE identifier, e.g. "CWE-89". Leave empty if unknown.
        evidence_request: The HTTP request or command that triggered it.
        evidence_response: The relevant response output.
        evidence_excerpt: A short excerpt highlighting the issue.
        repro: Reproduction steps, one per line.
        tool_chain: Tools used in this chain, comma-separated
            (e.g. "nmap, zap_open_url, zap_alerts").
    """
    evidence: Dict[str, str] = {}
    if evidence_request:
        evidence["request"] = evidence_request
    if evidence_response:
        evidence["response"] = evidence_response
    if evidence_excerpt:
        evidence["excerpt"] = evidence_excerpt

    repro_list: List[str] = (
        [s.strip() for s in repro.split("\n") if s.strip()] if repro else []
    )
    if isinstance(tool_chain, list):tool_chain = ",".join(str(s).strip() for s in tool_chain if str(s).strip())
    chain_list: List[str] = (
        [s.strip() for s in tool_chain.split(",") if s.strip()] if tool_chain else []
    )

    store = FindingStore()
    try:
        # Pre-generate a memory_id so we can store it as memory_ref.
        memory_id = f"finding-{int(time.time())}-{uuid4().hex[:6]}"
        pointer = f"{severity} {title} on {asset}"
        if cwe:
            pointer += f" ({cwe})"

        # Store a one-line pointer in vector memory — NOT the full finding.
        try:
            remember_text(text=pointer, namespace="findings", memory_id=memory_id)
        except Exception as exc:
            # Memory write failure is non-fatal — the finding is still stored.
            memory_id = None

        finding = store.add(
            title=title,
            severity=severity,
            asset=asset,
            cwe=cwe or None,
            evidence=evidence,
            repro=repro_list,
            tool_chain=chain_list,
            memory_ref=memory_id,
        )
        return (
            f"Finding {finding.id} reported: {title} ({severity}) on {asset}. "
            f"Use render_findings to review all findings."
        )
    finally:
        store.close()


@framework_tool(
    "Render all reported findings as a markdown report. Optionally filter by "
    "severity (P1/P2/P3/P4) or asset substring. Useful for reviewing progress "
    "mid-session or generating a submission draft at the end of an engagement. "
    "The report is also written to a timestamped .md file under findings_md/ "
    "so it persists outside the database."
)
def render_findings(severity: str = "", asset: str = "") -> str:
    """Render findings from the store as a markdown report.

    Args:
        severity: Filter to a specific severity (P1/P2/P3/P4). Empty = all.
        asset: Filter to findings whose asset contains this substring. Empty = all.
    """
    store = FindingStore()
    try:
        md = store.render_markdown(
            severity=severity or None,
            asset=asset or None,
        )
        out_path = store.write_markdown(
            severity=severity or None,
            asset=asset or None,
        )
        return (
            f"{md}\n\n"
            f"_Report written to: {out_path}_"
        )
    finally:
        store.close()
