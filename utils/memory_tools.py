"""Secretary-friendly memory tools that hide embedding computation.

``MemoryService.remember`` / ``recall`` require a precomputed embedding
vector, which a chat-model secretary cannot produce (it has no embedding
model and no way to call one).  That made the memory tools effectively
uncallable through the secretary loop, so ``memories.py`` was skip-listed
during tool discovery and turns 13/14 of the e2e runner were silently
SKIPPED -- a false green.

These thin wrappers take plain text, compute the embedding via Ollama, and
delegate to the shared :class:`MemoryService` so the secretary can store
and recall findings in conversation without ever touching a vector.  They
are plain ``@framework_tool`` functions under an allowed tool root, so they
are discovered and indexed like any other tool (run ``--reindex`` after
bootstrap to embed them).  The raw ``MemoryService`` is left untouched for
callers that supply their own embeddings.

NOTE on scope: the framework does not auto-persist tool results to memory,
so recall can only surface items that were explicitly stored via
``remember_text``.  Auto-persisting every finding is a separate (larger)
framework feature; these tools make the explicit store/recall path work.
"""

from __future__ import annotations

import os
import time
from typing import List

import httpx

from constants import framework_tool
from memories import _default_service as _svc

# Derive the Ollama embed endpoint from OLLAMA_BASE_URL, stripping a trailing
# /v1 if present (the chat-completions base URL carries it; the native embed
# API lives at /api/embed on the bare base).
_OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
if _OLLAMA_BASE.endswith("/v1"):
    _OLLAMA_BASE = _OLLAMA_BASE[:-3]
_EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")


def _embed(text: str) -> List[float]:
    """Synchronously embed a single text via Ollama's native embed endpoint.

    Runs in a worker thread (the executor dispatches sync tools via
    ``asyncio.to_thread``), so the blocking HTTP call never pins the loop.
    """
    resp = httpx.post(
        f"{_OLLAMA_BASE}/api/embed",
        json={"model": _EMBED_MODEL, "input": [text]},
        timeout=60.0,
    )
    resp.raise_for_status()
    payload = resp.json()
    if "embeddings" in payload:
        return payload["embeddings"][0]
    if "embedding" in payload:
        return payload["embedding"]
    raise ValueError(f"Unexpected Ollama embedding response: {payload}")


@framework_tool(
    "Store a fact or finding in persistent vector memory for later use. "
    "Supply the text to remember (e.g. 'root password on the box is toor'). "
    "Optionally give a namespace (default 'engagement') and a memory_id; if "
    "memory_id is omitted a unique one is generated. Pass your agent_id so "
    "the memory is tagged to you; omit it to write to the shared pool. Set "
    "important=true for critical findings you do not want anyone to be able "
    "to delete. Returns a stored confirmation naming the namespace and id."
)
def remember_text(text: str, namespace: str = "engagement", memory_id: str = "", agent_id: str = "", important: bool = False):
    """Remember a piece of text under a namespace.

    The embedding is computed automatically from ``text``; the caller never
    supplies a vector. ``agent_id`` (when non-empty) tags the entry to the
    running model so concurrent agents keep disjoint memory banks. ``important``
    marks the entry as protected — ``forget`` will refuse to delete it and
    counts any attempt as a strike against the caller.
    """
    if not memory_id:
              memory_id = f"mem-{int(time.time())}-{uuid4().hex[:6]}"
    embedding = _embed(text)
    _svc.remember(
        namespace=namespace,
        memory_id=memory_id,
        text=text,
        embedding=embedding,
        agent_id=(agent_id or None),
        important=bool(important),
    )
    return f"Memory stored in namespace '{namespace}': {memory_id} = {text}"


@framework_tool(
    "Recall earlier findings from persistent vector memory using a "
    "natural-language query. Pass a query describing what you want back "
    "(e.g. 'port 21 ftp findings' or 'root password') and optionally the "
    "namespace (default 'engagement'). Pass your agent_id to recall only "
    "your own memories; omit it to search the shared pool across all agents. "
    "Returns the closest stored matches by vector similarity."
)
def recall_text(query: str, namespace: str = "engagement", limit: int = 5, agent_id: str = ""):
    """Recall stored memories by semantic similarity to the query text."""
    query_embedding = _embed(query)
    return _svc.recall(
        namespace=namespace,
        query_embedding=query_embedding,
        limit=limit,
        agent_id=(agent_id or None),
    )
