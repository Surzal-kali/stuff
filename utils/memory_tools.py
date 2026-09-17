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
from uuid import uuid4

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
    "Store a fact or finding in persistent vector memory for later recall. "
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

    Args:
        text: The fact/finding to store. Write it self-contained (ids, hosts,
            severity, dates) — it is stored verbatim as the document.
        namespace: Flat namespace to store under (default 'engagement').
            Must already exist or it is silently AUTO-CREATED on write —
            verify with list_text_namespaces first when unsure.
        memory_id: Optional stable id (e.g. 'eng_crtsh_recon_recipe'). A
            unique generated id is used when empty; reusing an id UPSERTS.
        agent_id: Optional owner tag (the running model/agent). Empty =
            shared pool, recallable by every agent.
        important: Mark protected: forget refuses to delete it and counts
            any deletion attempt as a strike (3 strikes = lockout).
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
    "natural-language phrase. Pass a phrase describing what you want back "
    "(e.g. 'port 21 ftp findings' or 'root password') and optionally the "
    "namespace (default 'engagement'). Pass your agent_id to recall only "
    "your own memories; omit it to probe the shared pool across all agents. "
    "Returns the closest stored matches by vector similarity."
)
def recall_text(query: str, namespace: str = "engagement", limit: int = 5, agent_id: str = ""):
    """Recall stored memories by semantic similarity to the query text.

    Args:
        query: Natural-language phrase describing what you want back; it is
            embedded (nomic-embed-text) and matched by cosine similarity.
        namespace: Flat namespace to recall from (default 'engagement').
        limit: Max hits to return (default 5).
        agent_id: Optional owner filter. Leave EMPTY to search the shared
            pool across all agents (recommended — most entries are untagged
            or written by other sessions).
    """
    query_embedding = _embed(query)
    return _svc.recall(
        namespace=namespace,
        query_embedding=query_embedding,
        limit=limit,
        agent_id=(agent_id or None),
    )


@framework_tool(
    "List every memory namespace that currently has a stored collection. "
    "Namespaces auto-create on first write, so a typo'd namespace silently "
    "returns [] from recall_text and pollutes the store — verify a namespace "
    "exists here before using it. Returns sorted plain names (flat scheme, "
    "e.g. 'engagement', 'ops'); no prefix, no path separators."
)
def list_text_namespaces() -> List[str]:
    """List all memory namespaces that exist in the vector store."""
    return _svc.list_namespaces()

