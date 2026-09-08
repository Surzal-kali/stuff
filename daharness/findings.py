"""SQLite-backed findings store — the single source of truth for reported findings.

The store lives in ``ids.db`` (the same SQLite database used by
:class:`utils.sessions.DatabaseManager`).  Findings are written by the
``report_finding`` framework tool and read by ``render_findings``.  The full
Finding objects never enter the secretary model's context — only short
one-line pointers are stored in vector memory via ``remember_text``.

The markdown renderer in :meth:`FindingStore.render_markdown` doubles as a
bug-bounty submission draft and lab documentation, all from the same data.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .models import Finding

_DEFAULT_DB = str(Path(__file__).resolve().parent.parent / "ids.db")


class FindingStore:
    """Append-only findings store backed by a SQLite table in ``ids.db``."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_table()

    def _init_table(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                severity    TEXT NOT NULL,
                cwe         TEXT,
                asset       TEXT NOT NULL,
                evidence    TEXT,
                repro       TEXT,
                tool_chain  TEXT,
                memory_ref  TEXT,
                ts          TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    # -- write --------------------------------------------------------------

    def add(
        self,
        title: str,
        severity: str,
        asset: str,
        cwe: Optional[str] = None,
        evidence: Optional[dict] = None,
        repro: Optional[List[str]] = None,
        tool_chain: Optional[List[str]] = None,
        memory_ref: Optional[str] = None,
    ) -> Finding:
        """Append a finding, auto-assigning an incremental ID and timestamp."""
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        count = cur.fetchone()[0]
        finding_id = f"F-{count + 1:03d}"
        ts = datetime.now(timezone.utc).isoformat()

        finding = Finding(
            id=finding_id,
            title=title,
            severity=severity,
            cwe=cwe,
            asset=asset,
            evidence=evidence or {},
            repro=repro or [],
            tool_chain=tool_chain or [],
            memory_ref=memory_ref,
            ts=ts,
        )

        self.conn.execute(
            """
            INSERT INTO findings
                (id, title, severity, cwe, asset, evidence, repro, tool_chain, memory_ref, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.title,
                finding.severity,
                finding.cwe,
                finding.asset,
                json.dumps(finding.evidence),
                json.dumps(finding.repro),
                json.dumps(finding.tool_chain),
                finding.memory_ref,
                finding.ts,
            ),
        )
        self.conn.commit()
        return finding

    # -- read ---------------------------------------------------------------

    def all(self) -> List[Finding]:
        """Return all findings, oldest first (numeric ID order)."""
        # Sort by the integer portion of the ID (F-001 → 1, F-1000 → 1000)
        # so F-1000 doesn't sort before F-999 as it would lexicographically.
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY CAST(SUBSTR(id, 3) AS INTEGER) ASC"
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get(self, finding_id: str) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        return cur.fetchone()[0]

    # -- render -------------------------------------------------------------

    def render_markdown(
        self, severity: Optional[str] = None, asset: Optional[str] = None
    ) -> str:
        """Render findings as a markdown report.

        Optionally filter by severity (e.g. ``"P1"``) or asset substring.
        The output is suitable as a bug-bounty submission draft or lab
        documentation.
        """
        findings = self.all()
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if asset:
            findings = [f for f in findings if asset.lower() in f.asset.lower()]

        if not findings:
            return "_(no findings reported yet)_"

        lines = [f"# Findings Report ({len(findings)} finding(s))", ""]

        # Summary table
        lines.append("| ID | Title | Severity | CWE | Asset |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(
                f"| {f.id} | {f.title} | {f.severity} | {f.cwe or '—'} | {f.asset} |"
            )
        lines.append("")

        for f in findings:
            lines.append(f"## {f.id}: {f.title} ({f.severity})")
            lines.append("")
            lines.append(f"**Asset:** {f.asset}")
            lines.append(f"**CWE:** {f.cwe or '—'}")
            lines.append(f"**Timestamp:** {f.ts}")
            if f.memory_ref:
                lines.append(f"**Memory ref:** {f.memory_ref}")
            lines.append("")

            if f.evidence:
                lines.append("### Evidence")
                lines.append("")
                for key in ("request", "response", "excerpt"):
                    val = f.evidence.get(key)
                    if val:
                        lines.append(f"**{key.title()}:**")
                        lines.append(f"```")
                        lines.append(val)
                        lines.append("```")
                        lines.append("")

            if f.repro:
                lines.append("### Reproduction")
                lines.append("")
                for i, step in enumerate(f.repro, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            if f.tool_chain:
                lines.append("### Tool Chain")
                lines.append("")
                lines.append(" → ".join(f.tool_chain))
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            title=row["title"],
            severity=row["severity"],
            cwe=row["cwe"],
            asset=row["asset"],
            evidence=json.loads(row["evidence"] or "{}"),
            repro=json.loads(row["repro"] or "[]"),
            tool_chain=json.loads(row["tool_chain"] or "[]"),
            memory_ref=row["memory_ref"],
            ts=row["ts"],
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
