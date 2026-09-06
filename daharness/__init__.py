"""Modular tool harness public API.

The implementation is split across focused submodules:

* :mod:`daharness.models`    — ``ToolManifest`` data model.
* :mod:`daharness.registry`  — config, ``OllamaEmbeddingFunction``, ``ToolRegistry``.
* :mod:`daharness.executor`  — execution/dispatch (mixed into ``ToolRegistry``).
* :mod:`daharness.agent`     — the secretary agent loop (mixed into ``ToolRegistry``).

This package init re-exports the public surface for callers that import from
``daharness`` directly. ``daharness.core`` remains as a thin backwards-compat
shim so ``python3 daharness/core.py`` keeps working.
"""

import sys
from pathlib import Path

# Make the project root importable for `from constants import ...` used by the
# submodules, regardless of how the package is loaded (and when core.py is run
# as a script, which imports these submodules via absolute import).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Re-export httpx so callers (and tests) can monkeypatch the shared module
# object via `daharness.httpx`. registry.py imports the same `httpx` module, so
# patching `daharness.httpx.AsyncClient` is seen by ToolRegistry._embed_text.
# Not added to __all__ - httpx is an internal dependency, not a public API type.
import httpx

from .models import ToolManifest
from .registry import OllamaEmbeddingFunction, ToolRegistry
from .agent import (
    SecretaryDeps,
    _chat,
    _cli_confirmer,
    _parse_tool_args,
    _run_confirmer,
    create_secretary_agent,
    secretary_execute_tool,
    secretary_search_tools,
)

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
