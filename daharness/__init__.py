"""Modular tool harness public API.

The implementation lives in :mod:`daharness.core` for backwards-compatible
behavior while the package modules expose focused import paths for callers.
"""

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
