"""Process-local store for long-lived/hanging tool sessions.

When a tool establishes a connection that must survive beyond the tool call
that created it (an SSH client, an MSF session, a database handle, ...), it
registers the live object here and receives a ``session_id``.  Subsequent
tool calls pass that ``session_id`` to retrieve the live object and interact
with it.  A dedicated ``close`` tool (or stale-session cleanup) tears it down.

This is a **process-local singleton**.  Whichever process actually runs the
tool -- the Brain sidecar (``listeners/thebrain.py``) or the in-process
launcher inside the ToolRegistry -- holds the sessions it created.  As long
as all calls for a given session go through the same process (which they do
when the Brain is up, the normal path), sessions are consistent.  If the
Brain dies and a later call falls back in-process, that call cannot see
sessions the Brain was holding -- a known limitation of the dual-dispatch
design.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """A single live session held by the manager."""

    sid: str
    kind: str  # "ssh", "msf_shell", "meterpreter", ...
    target: str  # human-readable, e.g. "root@10.0.0.5:22"
    client: Any  # the live connection object (paramiko.SSHClient, MSF session, ...)
    created_at: float
    last_activity: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.last_activity = time.time()


class SessionManager:
    """Thread-safe singleton holding live session objects keyed by session ID.

    Use :meth:`get_manager` (or instantiate, which returns the shared
    instance) to obtain the singleton.  Tools call :meth:`register` when they
    open a connection and :meth:`get` when they need to interact with one.
    """

    _instance: Optional["SessionManager"] = None
    _instance_lock = threading.Lock()

    def __new__(cls) -> "SessionManager":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._sessions: Dict[str, Session] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._initialized = True

    # -- public API --------------------------------------------------------

    def register(
        self,
        kind: str,
        target: str,
        client: Any,
        **metadata: Any,
    ) -> str:
        """Store a live connection and return a unique ``session_id``."""
        with self._lock:
            sid = f"sess-{self._next_id:04d}"
            self._next_id += 1
            now = time.time()
            self._sessions[sid] = Session(
                sid=sid,
                kind=kind,
                target=target,
                client=client,
                created_at=now,
                last_activity=now,
                metadata=dict(metadata),
            )
            logger.info(
                "[SessionManager] Registered %s session %s -> %s", kind, sid, target
            )
            return sid

    def get(self, sid: str) -> Optional[Session]:
        """Retrieve a live session by ID, updating its activity timestamp."""
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                session.touch()
            return session

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Return a list of session summaries (no live objects)."""
        with self._lock:
            return [
                {
                    "sid": s.sid,
                    "kind": s.kind,
                    "target": s.target,
                    "created_at": s.created_at,
                    "last_activity": s.last_activity,
                    "metadata": dict(s.metadata),
                }
                for s in self._sessions.values()
            ]

    def close(self, sid: str) -> bool:
        """Close and remove a session. Returns ``True`` if it existed."""
        with self._lock:
            session = self._sessions.pop(sid, None)
        if session is None:
            return False
        self._safe_close(session)
        logger.info("[SessionManager] Closed session %s", sid)
        return True

    def cleanup_stale(self, max_idle_seconds: float = 3600.0) -> int:
        """Close sessions idle longer than ``max_idle_seconds``. Returns count closed."""
        now = time.time()
        with self._lock:
            stale = [
                sid
                for sid, s in self._sessions.items()
                if now - s.last_activity > max_idle_seconds
            ]
        closed = 0
        for sid in stale:
            if self.close(sid):
                closed += 1
        if closed:
            logger.info(
                "[SessionManager] Cleaned up %d stale sessions (idle > %ss)",
                closed,
                max_idle_seconds,
            )
        return closed

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _safe_close(session: Session) -> None:
        """Best-effort close of the underlying client object."""
        client = session.client
        close_fn = getattr(client, "close", None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception as exc:
                logger.warning(
                    "[SessionManager] Error closing %s (%s): %s",
                    session.sid,
                    session.kind,
                    exc,
                )


def get_manager() -> SessionManager:
    """Convenience accessor for the shared SessionManager singleton."""
    return SessionManager()
