"""Secretary agent API.

The agent implementation remains centralized in ``core`` so existing
conversation and approval behavior is unchanged.
"""

from .core import (
    SecretaryDeps,
    _cli_confirmer,
    _parse_tool_args,
    _run_confirmer,
    secretary_execute_tool,
    secretary_search_tools,
)


def create_secretary_agent(registry, model=None):
    """Create the secretary configured for a registry."""
    return registry._init_secretary_agent(model=model)

__all__ = [
    "SecretaryDeps",
    "create_secretary_agent",
    "secretary_execute_tool",
    "secretary_search_tools",
    "_cli_confirmer",
    "_parse_tool_args",
    "_run_confirmer",
]
