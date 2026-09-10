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
        # --- migrations: add lifecycle columns to pre-existing tables ---
        # ALTER TABLE ... ADD COLUMN is idempotent-safe: we check the existing
        # columns first and only add the ones that are missing.  This lets the
        # store work on both fresh databases and ones with legacy schema.
        existing_cols = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        migrations = [
            ("status", "TEXT NOT NULL DEFAULT 'open'"),
            ("superseded_by", "TEXT"),
            ("closed_by", "TEXT"),
            ("closed_reason", "TEXT"),
            ("closed_ts", "TEXT"),
        ]
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                self.conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}"
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
                            (id, title, severity, cwe, asset, evidence, repro,
                             tool_chain, memory_ref, ts, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
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

    # -- lifecycle (close / supersede / reopen) ----------------------------

    _VALID_STATUSES = {"open", "closed", "superseded", "false_positive", "duplicate"}

    def update_status(
        self,
        finding_id: str,
        status: str,
        closed_by: Optional[str] = None,
        closed_reason: Optional[str] = None,
        superseded_by: Optional[str] = None,
    ) -> Optional[Finding]:
        """Update the lifecycle status of a finding.

        Args:
            finding_id: The finding ID (e.g. ``F-008``).
            status: One of open|closed|superseded|false_positive|duplicate.
            closed_by: Who/what closed it (agent name, role, etc.).
            closed_reason: Free-text explanation.
            superseded_by: When status is "superseded", the ID of the
                replacement finding.  The target finding must exist.

        Returns the updated :class:`Finding`, or ``None`` if not found.
        Raises ``ValueError`` for an invalid status or bad supersede target.
        """
        if status not in self._VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: "
                f"{', '.join(sorted(self._VALID_STATUSES))}"
            )

        finding = self.get(finding_id)
        if finding is None:
            return None

        # Validate supersede target
        if status == "superseded":
            if not superseded_by:
                raise ValueError("superseded_by is required when status is 'superseded'")
            replacement = self.get(superseded_by)
            if replacement is None:
                raise ValueError(f"Supersede target {superseded_by} does not exist")
            if superseded_by == finding_id:
                raise ValueError("A finding cannot supersede itself")

        # Prevent circular supersede chains
        if superseded_by and superseded_by != finding_id:
            chain = self._supersede_chain(superseded_by)
            if finding_id in chain:
                raise ValueError(
                    f"Circular supersede: {superseded_by} is itself superseded "
                    f"(directly or transitively) by {finding_id}"
                )

        ts = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                UPDATE findings
                SET status = ?, superseded_by = ?, closed_by = ?,
                    closed_reason = ?, closed_ts = ?
                WHERE id = ?
                """,
                (status, superseded_by, closed_by, closed_reason, ts, finding_id),
            )
        return self.get(finding_id)

    def supersede(
        self,
        old_id: str,
        new_id: str,
        closed_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> dict:
        """Mark ``old_id`` as superseded by ``new_id``.

        This is the common case: an agent reports a refined/corrected finding
        and wants to close the older one with a pointer to the replacement.
        Both findings must already exist in the store.

        Returns ``{old: Finding, new: Finding}`` as dicts for convenience.
        """
        old = self.get(old_id)
        if old is None:
            raise ValueError(f"Finding {old_id} not found")
        new = self.get(new_id)
        if new is None:
            raise ValueError(f"Finding {new_id} not found")
        if old_id == new_id:
            raise ValueError("A finding cannot supersede itself")

        updated = self.update_status(
            old_id,
            status="superseded",
            closed_by=closed_by,
            closed_reason=reason or f"Superseded by {new_id}",
            superseded_by=new_id,
        )
        return {"old": updated, "new": new}

    def _supersede_chain(self, finding_id: str) -> set:
        """Return the set of all IDs that ``finding_id`` is superseded by
        (transitively), for circular-chain detection."""
        seen = set()
        current = finding_id
        while current:
            if current in seen:
                break  # already detected a cycle in the existing chain
            seen.add(current)
            row = self.conn.execute(
                "SELECT superseded_by FROM findings WHERE id = ?", (current,)
            ).fetchone()
            current = row["superseded_by"] if row else None
        return seen

    # -- read (with status awareness) ---------------------------------------

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        return cur.fetchone()[0]

    # -- render -------------------------------------------------------------

    def render_markdown(
        self,
        severity: Optional[str] = None,
        asset: Optional[str] = None,
        status: Optional[str] = None,
        include_closed: bool = True,
    ) -> str:
        """Render findings as a markdown report.

        Optionally filter by severity (e.g. ``"P1"``), asset substring, or
        status (e.g. ``"open"``).  When ``include_closed`` is ``False``,
        only open findings are shown regardless of the ``status`` filter —
        useful for a "current state" report that hides superseded / false
        positive / duplicate entries.

        The output is suitable as a bug-bounty submission draft or lab
        documentation.
        """
        findings = self.all()
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if asset:
            findings = [f for f in findings if asset.lower() in f.asset.lower()]
        if status:
            findings = [f for f in findings if f.status == status]
        if not include_closed:
            findings = [f for f in findings if f.status == "open"]

        if not findings:
            return "_(no findings reported yet)_"

        # Status breakdown for the header
        open_count = sum(1 for f in findings if f.status == "open")
        closed_count = len(findings) - open_count
        header = f"# Findings Report ({len(findings)} finding(s)"
        if closed_count:
            header += f", {open_count} open / {closed_count} closed"
        header += ")"

        lines = [header, ""]

        # Summary table
        lines.append("| ID | Title | Severity | CWE | Asset | Status |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            status_cell = f.status
            if f.superseded_by:
                status_cell += f" → {f.superseded_by}"
            lines.append(
                f"| {f.id} | {f.title} | {f.severity} | {f.cwe or '—'} | {f.asset} | {status_cell} |"
            )
        lines.append("")

        for f in findings:
            status_tag = f" [{f.status}]" if f.status != "open" else ""
            lines.append(f"## {f.id}: {f.title} ({f.severity}){status_tag}")
            lines.append("")
            lines.append(f"**Asset:** {f.asset}")
            lines.append(f"**CWE:** {f.cwe or '—'}")
            lines.append(f"**Timestamp:** {f.ts}")
            if f.memory_ref:
                lines.append(f"**Memory ref:** {f.memory_ref}")
            if f.status != "open":
                lines.append(f"**Status:** {f.status}")
                if f.superseded_by:
                    lines.append(f"**Superseded by:** {f.superseded_by}")
                if f.closed_by:
                    lines.append(f"**Closed by:** {f.closed_by}")
                if f.closed_reason:
                    lines.append(f"**Closure reason:** {f.closed_reason}")
                if f.closed_ts:
                    lines.append(f"**Closed at:** {f.closed_ts}")
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

    def write_markdown(
        self,
        output_dir: Optional[Path] = None,
        severity: Optional[str] = None,
        asset: Optional[str] = None,
        status: Optional[str] = None,
        include_closed: bool = True,
    ) -> Path:
        """Render findings to markdown AND persist the report to disk.

        Writes a timestamped ``.md`` file under ``output_dir`` (defaults to
        ``<workspace_root>/findings_md/``).  Each call produces a new file so
        successive snapshots don't clobber each other.  Returns the path to
        the written file.

        The output dir is created if it doesn't exist.  Filters work the
        same as :meth:`render_markdown`.
        """
        md = self.render_markdown(
            severity=severity, asset=asset, status=status,
            include_closed=include_closed,
        )

        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "findings_md"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        parts = [ts]
        if severity:
            parts.append(severity)
        if asset:
            parts.append(asset.replace("/", "_").replace(" ", "_"))
        filename = "findings_" + "-".join(parts) + ".md"
        out_path = output_dir / filename
        out_path.write_text(md, encoding="utf-8")
        return out_path

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
            status=row["status"] if "status" in row.keys() else "open",
            superseded_by=row["superseded_by"] if "superseded_by" in row.keys() else None,
            closed_by=row["closed_by"] if "closed_by" in row.keys() else None,
            closed_reason=row["closed_reason"] if "closed_reason" in row.keys() else None,
            closed_ts=row["closed_ts"] if "closed_ts" in row.keys() else None,
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
