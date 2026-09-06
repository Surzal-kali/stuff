"""Modular tool harness public API.

The implementation lives in :mod:`daharness.core` for backwards-compatible
behavior while the package modules expose focused import paths for callers.
"""

# Re-export httpx so callers (and tests) can monkeypatch the shared module
# object via `daharness.httpx`. core.py imports the same `httpx` module, so
# patching `daharness.httpx.AsyncClient` is seen by core._embed_text. Not
# added to __all__ - httpx is an internal dependency, not a public API type.
import httpx

from .core import (
    OllamaEmbeddingFunction,
    SecretaryDeps,
    ToolManifest,
    ToolRegistry,
    _chat,
    _cli_confirmer,
    _parse_tool_args,
    _run_confirmer,
    secretary_execute_tool,
    secretary_search_tools,
)
from .agent import create_secretary_agent

__all__ = [
    "OllamaEmbeddingFunction",
    "create_secretary_agent",
    "SecretaryDeps",
    "ToolManifest",
    "ToolRegistry",
    "_chat",
    "_cli_confirmer",
    "_parse_tool_args",
    "_run_confirmer",
    "secretary_execute_tool",
    "secretary_search_tools",
]
