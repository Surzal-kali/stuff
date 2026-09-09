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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4
from .models import Finding

_DEFAULT_DB = str(Path(__file__).resolve().parent.parent / "ids.db")


class FindingStore:
    """Append-only findings store backed by a SQLite table in ``ids.db``."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, timeout=10.0)
        self.conn.row_factory = sqlite3.Row
        # busy_timeout FIRST so every later statement (including the WAL
        # pragma and table init) waits on locks instead of erroring out.
        self.conn.execute("PRAGMA busy_timeout=10000")
        # WAL: readers don't block the writer and vice versa across
        # processes (gateway, secretary, MCP clients all share ids.db).
        # Switching INTO wal mode requires the global write lock, so under
        # concurrent connects the pragma itself can raise 'database is
        # locked'. It only needs to happen once per database file: skip it
        # when the file is already WAL, and retry the connect loop below
        # otherwise.
        # Cold-start note: on a brand-new file every concurrent connect
        # sees non-WAL mode and races on the journal_mode pragma, which
        # needs an exclusive lock that busy_timeout does NOT cover. So the
        # whole setup retries; only the first process ever flips the file
        # into WAL, after which every later connect skips the pragma.
        for _attempt in range(5):
            try:
                mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    self.conn.execute("PRAGMA journal_mode=WAL")
                self._init_table()
                break
            except sqlite3.OperationalError:
                if _attempt == 4:
                    raise
                self.conn.rollback()
                time.sleep(0.05 * (_attempt + 1))

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
        ts = datetime.now(timezone.utc).isoformat()

        # Concurrent adds (gateway + secretary + MCP clients all share
        # ids.db) can compute the same F-id; the PRIMARY KEY turns that
        # into a loud IntegrityError instead of a duplicate. Recount and
        # retry so the caller just gets their finding, slightly later.
        last_exc: Optional[BaseException] = None
        for _attempt in range(10):
            cur = self.conn.execute("SELECT COUNT(*) FROM findings")
            finding_id = f"F-{cur.fetchone()[0] + 1:03d}"
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
            try:
                with self.conn:  # atomic INSERT + commit
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
                return finding
            except sqlite3.IntegrityError:
                finding.id = f"F-{uuid4()}"  # lost the id race - generate a new one and retry
            except sqlite3.OperationalError as exc:
                last_exc = exc  # e.g. 'database is locked' after busy_timeout
        if last_exc:
            raise last_exc
        raise RuntimeError("could not assign a unique finding ID after 3 attempts")

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
