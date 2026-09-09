"""Framework health check tool — owns the 'health check' / 'framework status' vocabulary.

This module exists to be the rightful owner of the words 'health check',
'framework status', and 'system health' in the tool vector space.  Without
a dedicated tool carrying that vocabulary, a vague intent like 'framework
health status check' resolved to whatever sibling happened to win the
cosine tie (verified live: it ran a ZAP spider-status read).  By giving
these words a single rightful home with a distinctive, non-colliding
description, the router dispatches health intents here instead of to a
wrong sibling.

The tool probes the framework's key subsystems and returns a structured
JSON report.  It is read-only and side-effect-free — safe to call at any
point in a session to verify the harness is alive.
"""

from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict

from constants import framework_tool


def _check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    """TCP connect probe — True if the port accepts a connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _check_unix_socket(path: str) -> bool:
    """Unix domain socket probe — True if the socket file exists and is a socket."""
    p = Path(path)
    return p.is_socket()


@framework_tool(
    "Report the operational health of the penetration testing framework: "
    "Brain sidecar socket, Ollama LLM/embedding endpoints, ChromaDB vector "
    "store, ZAP daemon, and SQLite findings database. Returns a structured "
    "JSON report with per-subsystem up/down verdicts and the tool count "
    "in the registry. Use this to verify the harness is alive before "
    "starting an engagement or after a crash."
)
def framework_health() -> Dict[str, Any]:
    """Probe framework subsystems and return a health report.

    Checks:
    - Brain sidecar UDS socket at /tmp/brain.sock
    - Ollama API at the configured OLLAMA_BASE_URL
    - ChromaDB at the configured CHROMA_HOST:CHROMA_PORT
    - ZAP daemon at the configured ZAP_PORT
    - SQLite findings database at ids.db

    Returns a dict with ``overall`` (``"ok"`` / ``"degraded"``), a
    ``subsystems`` map of name -> {``up``: bool, ``detail``: str}, and
    ``tool_count`` if ChromaDB is reachable.
    """
    ollama_base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    # Strip /v1 for the raw API probe.
    ollama_raw = ollama_base.rstrip("/")
    if ollama_raw.endswith("/v1"):
        ollama_raw = ollama_raw[:-3]
    ollama_host = "localhost"
    ollama_port = 11434
    try:
        from urllib.parse import urlparse
        parsed = urlparse(ollama_raw)
        ollama_host = parsed.hostname or "localhost"
        ollama_port = parsed.port or 11434
    except Exception:
        pass

    chroma_host = os.getenv("CHROMA_HOST", "localhost")
    chroma_port = int(os.getenv("CHROMA_PORT", "9000"))
    zap_port = int(os.getenv("ZAP_PORT", "8090"))

    workspace = Path(os.getenv("WORKSPACE_ROOT", os.getcwd())).resolve()
    db_path = workspace / "ids.db"

    subsystems: Dict[str, Dict[str, Any]] = {}

    # Brain sidecar
    brain_up = _check_unix_socket("/tmp/brain.sock")
    subsystems["brain_sidecar"] = {
        "up": brain_up,
        "detail": "/tmp/brain.sock reachable" if brain_up else "socket not found — sidecar is down",
    }

    # Ollama
    ollama_up = _check_tcp(ollama_host, ollama_port)
    subsystems["ollama"] = {
        "up": ollama_up,
        "detail": f"{ollama_host}:{ollama_port} (LLM + embedding)" if ollama_up else f"unreachable at {ollama_host}:{ollama_port}",
    }

    # ChromaDB
    chroma_up = _check_tcp(chroma_host, chroma_port)
    tool_count = None
    if chroma_up:
        try:
            import chromadb
            client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
            coll = client.get_or_create_collection(
                name="tool_inventory",
                embedding_function=type("DummyEF", (), {
                    "__call__": lambda self, input: [[0.0] * 768],
                    "name": lambda self: "dummy",
                })(),
            )
            tool_count = len(coll.get(include=[]).get("ids", []))
        except Exception as exc:
            chroma_up = False
            subsystems["chromadb"] = {"up": False, "detail": f"reachable but error: {exc}"}
    subsystems.setdefault("chromadb", {
        "up": chroma_up,
        "detail": f"{chroma_host}:{chroma_port}" if chroma_up else f"unreachable at {chroma_host}:{chroma_port}",
    })
    if tool_count is not None:
        subsystems["chromadb"]["tool_count"] = tool_count

    # ZAP daemon
    zap_up = _check_tcp("127.0.0.1", zap_port)
    subsystems["zap_daemon"] = {
        "up": zap_up,
        "detail": f"127.0.0.1:{zap_port}" if zap_up else f"not listening on 127.0.0.1:{zap_port}",
    }

    # SQLite findings DB
    db_exists = db_path.exists()
    db_up = db_exists
    if db_exists:
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path), timeout=2.0)
            conn.execute("SELECT 1 FROM findings LIMIT 1")
            conn.close()
        except Exception as exc:
            db_up = False
            subsystems["findings_db"] = {"up": False, "detail": f"exists but error: {exc}"}
    subsystems.setdefault("findings_db", {
        "up": db_up,
        "detail": str(db_path) if db_up else f"not found at {db_path}",
    })

    up_count = sum(1 for v in subsystems.values() if v["up"])
    total = len(subsystems)
    overall = "ok" if up_count == total else ("degraded" if up_count > 0 else "down")

    return {
        "overall": overall,
        "subsystems_up": f"{up_count}/{total}",
        "subsystems": subsystems,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
