import os
import json
import logging
import asyncio
import textwrap
import inspect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Callable
from pydantic_ai import (
    Agent,
    DeferredToolRequests,
    FunctionToolset,
    ModelRetry,
    RunContext,
    Tool,
)
from .models import ToolManifest
from .registry import ToolRegistry

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://100.66.181.0:11434/v1").rstrip("/")
SECRETARY_MODEL = os.getenv("SECRETARY_MODEL", "gemma4:12b")
SECRETARY_MAX_TOP_K = 10

@dataclass
class SecretaryDeps:
    registry: ToolRegistry
    surfaced_tools: Dict[str, ToolManifest] = field(default_factory=dict)

    def record_surfaced(self, manifests: List[ToolManifest]) -> None:
        for manifest in manifests:
            self.surfaced_tools[manifest.module_id] = manifest

    def get_surfaced(self, tool_id: str) -> Optional[ToolManifest]:
        return self.surfaced_tools.get(tool_id)

async def secretary_search_tools(ctx: RunContext[SecretaryDeps], query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    registry = ctx.deps.registry
    limit = max(1, min(int(top_k), SECRETARY_MAX_TOP_K))
    logger.info(f"[secretary] search_tools query={query!r} top_k={limit}")
    manifests = await registry.find_tools(query, top_k=limit)
    ctx.deps.record_surfaced(manifests)
    return [registry.describe_manifest(m) for m in manifests]

async def secretary_execute_tool(
    ctx: RunContext[SecretaryDeps],
    tool_id: str,
    arguments: Union[Dict[str, Any], str, None] = None,
) -> Dict[str, Any]:
    # Implementation from daharness.py...
    # This will call daharness.executor.execute_tool
    return {"status": "pending", "message": "Execution logic to be ported from daharness.py"}

def create_secretary_agent(registry: ToolRegistry, model_name: str = SECRETARY_MODEL):
    from pydantic_ai.models.ollama import OllamaModel
    from pydantic_ai.providers.ollama import OllamaProvider

    model = OllamaModel(model_name, provider=OllamaProvider(base_url=OLLAMA_BASE_URL))
    
    toolset = FunctionToolset([
        Tool(secretary_search_tools, takes_ctx=True, name="search_tools"),
        Tool(secretary_execute_tool, takes_ctx=True, name="execute_tool", requires_approval=True),
    ])

    instructions = textwrap.dedent("""\
        You are the tool secretary of a modular security framework.
        Workflow: search_tools -> pick tool_id -> execute_tool -> report.
        """)

    return Agent(
        model,
        deps_type=SecretaryDeps,
        output_type=[str, DeferredToolRequests],
        toolsets=[toolset],
        instructions=instructions,
        retries=2,
        name="tool_secretary",
    )
