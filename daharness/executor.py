"""Execution API exposed by the harness package."""

from .core import ToolManifest, ToolRegistry


def _new_registry():
    registry = ToolRegistry.__new__(ToolRegistry)
    registry._tool_instances = {}
    return registry


async def execute_tool(manifest: ToolManifest, arguments: dict):
    """Execute a manifest without creating a ChromaDB client.

    Registry-owned execution is preferred because it preserves cached class
    instances across calls. This helper exists for callers with one-off jobs.
    """
    return await _new_registry().execute_tool(manifest, arguments)


async def execute_local_script(script_path: str, arguments: dict):
    """Run a local manifest script using the shared execution rules."""
    return await _new_registry()._execute_local_script(script_path, arguments)


async def dispatch_via_brain(tool_id: str, arguments: dict):
    """Attempt Brain dispatch without constructing a registry client."""
    return await _new_registry()._dispatch_via_brain(tool_id, arguments)


async def launch_in_process(tool_id: str, arguments: dict):
    """Launch a decorated Python tool without constructing a registry client."""
    return await _new_registry()._launch_in_process(tool_id, arguments)


__all__ = [
    "dispatch_via_brain",
    "execute_local_script",
    "execute_tool",
    "launch_in_process",
    "ToolManifest",
    "ToolRegistry",
]
