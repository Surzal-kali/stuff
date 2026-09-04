import os
import json
import sys
import logging
import asyncio
import inspect
import textwrap
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
import httpx
from pydantic import BaseModel, Field, ValidationError
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from pydantic_ai import (
    Agent,
    DeferredToolRequests,
    FunctionToolset,
    ModelRetry,
    RunContext,
    Tool,
    ToolApproved,
    ToolDenied,
)

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- Configuration ---
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://100.66.181.0:11434/v1").rstrip("/")
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "9000"))
WORKSPACE_ROOT = Path(os.getenv("WORKSPACE_ROOT", os.getcwd())).resolve()
# The non-thinking LFM2.5 variant reliably drives the tool loop; the -thinking
# variant hallucinated tools/executions in live testing instead of calling them.
SECRETARY_MODEL = os.getenv("SECRETARY_MODEL", "lfm2.5:latest")
SECRETARY_MAX_TOP_K = 10
SECRETARY_MAX_APPROVAL_ROUNDS = int(os.getenv("SECRETARY_MAX_APPROVAL_ROUNDS", "8"))
ALLOWED_TOOL_ROOTS = [
    (WORKSPACE_ROOT / "auxiliaries").resolve(),
    (WORKSPACE_ROOT / "payloads").resolve(),
    (WORKSPACE_ROOT / "listeners").resolve(),
    (WORKSPACE_ROOT / "utils").resolve(),
    (WORKSPACE_ROOT / "encoders").resolve(),
]

# --- Transport Type ---
class TransportType(Enum):
    LOCAL_FILE = "local_file"
    MCP_RPC = "mcp_rpc"

# --- Ollama Embedding Function ---
class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __init__(self, model_name: str = "nomic-embed-text", base_url: str = OLLAMA_BASE_URL):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/v1")
        self.embed_url = f"{self.base_url}/api/embed"

    def __call__(self, texts: List[str]) -> List[List[float]]:
        async def embed_async():
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    self.embed_url,
                    json={"model": self.model_name, "input": texts},
                )
                response.raise_for_status()
                payload = response.json()
                if "embeddings" in payload:
                    return payload["embeddings"]
                raise ValueError(f"Unexpected Ollama embedding response: {payload}")

        return asyncio.run(embed_async())

    def name(self) -> str:
        return self.model_name

# --- Tool Manifest ---
class ToolManifest(BaseModel):
    module_id: str = Field(..., min_length=1)
    internal_semantic_capability: str = Field(..., min_length=1)
    external_sanitized_description: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    implementation_path: str = Field(..., min_length=1)
    internal_semantics: str = Field(..., min_length=1)
    transport: TransportType = TransportType.LOCAL_FILE
    endpoint: Optional[str] = None
    tool_name: Optional[str] = None

    @classmethod
    def from_output(cls, payload: Any) -> Union["ToolManifest", List["ToolManifest"]]:
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, list):
            # Ensure we flatten the result to avoid List[List[ToolManifest]]
            results: List["ToolManifest"] = []
            for item in payload:
                res = cls.from_output(item)
                if isinstance(res, list):
                    results.extend(res)
                else:
                    results.append(res)
            return results
        if isinstance(payload, dict):
            # Handle Metasploit module dictionary mapping
            # MSF modules usually have 'name' and 'description'
            if 'name' in payload or 'description' in payload:
                mapped_payload = {
                    "module_id": payload.get('name', 'unknown_module'),
                    "internal_semantic_capability": payload.get('description', 'No description provided'),
                    "external_sanitized_description": payload.get('description', 'No description provided'),
                    "implementation_path": f"msf://{payload.get('name', 'unknown_module')}",
                    "internal_semantics": payload.get('description', 'No description provided'),
                    "transport": TransportType.MCP_RPC,
                    "endpoint": "metasploit"
                }
                return cls.model_validate(mapped_payload)
            return cls.model_validate(payload)
        if hasattr(payload, "model_dump"):
            return cls.model_validate(payload.model_dump())
        raise TypeError(f"Unsupported ToolManifest payload: {type(payload).__name__}")

# --- Secretary (conversational tool agent) ---
#
# The secretary IS the agent loop now. There is no separate "final" model: the
# small secretary model semantic-searches the registry, picks a module and
# executes it, then reports. Executions are gated on human approval: the
# `execute_tool` tool is declared `requires_approval=True`, so every execution
# pauses the run, the confirmer is shown the FULL manifest plus arguments, and
# the run resumes with the approve/deny decision.


@dataclass
class SecretaryDeps:
    """Per-conversation state for the secretary agent.

    `surfaced_tools` is the grounding set: module ids the model has actually
    seen returned by `search_tools` in this conversation. `execute_tool`
    refuses ids outside it, so the model cannot hallucinate a tool into
    existence. Reuse one instance (plus the message history) to keep a
    conversation going across turns.
    """

    registry: "ToolRegistry"
    surfaced_tools: Dict[str, ToolManifest] = field(default_factory=dict)

    def record_surfaced(self, manifests: List[ToolManifest]) -> None:
        for manifest in manifests:
            self.surfaced_tools[manifest.module_id] = manifest

    def get_surfaced(self, tool_id: str) -> Optional[ToolManifest]:
        return self.surfaced_tools.get(tool_id)


async def _cli_confirmer(summary: Dict[str, Any]) -> bool:
    """Default human-in-the-loop gate: print full metadata, ask y/N on stdin."""
    print("\n===== EXECUTION CONFIRMATION =====")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("==================================")
    answer = await asyncio.to_thread(input, "Approve execution? [y/N]: ")
    return answer.strip().lower() in {"y", "yes"}


async def _run_confirmer(confirmer: Callable[[Dict[str, Any]], Any], summary: Dict[str, Any]) -> bool:
    result = confirmer(summary)
    if inspect.isawaitable(result):
        result = await result
    return bool(result)


def _parse_tool_args(args: Any) -> Dict[str, Any]:
    """ToolCallPart.args may be a dict or a JSON string; normalize defensively."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str) and args.strip():
        try:
            parsed = json.loads(args)
            return parsed if isinstance(parsed, dict) else {"_raw": args}
        except json.JSONDecodeError:
            return {"_raw": args}
    return {}


async def secretary_search_tools(
    ctx: RunContext[SecretaryDeps], query: str, top_k: int = 5
) -> List[Dict[str, Any]]:
    """Semantic search over the tool registry.

    Returns FULL manifests (id, capability, implementation path, transport,
    parameters, semantics). The tool_ids returned here are the only ids that
    `execute_tool` will accept.
    """
    registry = ctx.deps.registry
    limit = max(1, min(int(top_k or 5), SECRETARY_MAX_TOP_K))
    manifests = await registry.find_tools(query, top_k=limit)
    ctx.deps.record_surfaced(manifests)
    return [registry.describe_manifest(m) for m in manifests]


async def secretary_execute_tool(
    ctx: RunContext[SecretaryDeps], tool_id: str, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute a tool that was surfaced by `search_tools` in this conversation.

    This call requires human approval; a confirmation showing the full module
    metadata and the arguments is presented before anything runs.
    """
    registry = ctx.deps.registry
    tool_id = (tool_id or "").strip()

    manifest = ctx.deps.get_surfaced(tool_id)
    if manifest is None:
        if await registry.find_tool_by_id(tool_id):
            raise ModelRetry(
                f"Tool '{tool_id}' exists in the registry but was never surfaced in this conversation. "
                "Call `search_tools` first and use a tool_id taken verbatim from its results."
            )
        raise ModelRetry(
            f"Unknown tool_id '{tool_id}'. Call `search_tools` first and use a tool_id taken verbatim from its results."
        )

    args = arguments or {}
    warnings = registry.validate_arguments(manifest, args)
    result = await registry.execute_tool(manifest, args)
    if isinstance(result, dict) and warnings:
        result = {**result, "argument_warnings": warnings}
    return result


# --- Tool Registry ---
class ToolRegistry:
    def __init__(
        self,
        embedding_model: OllamaEmbeddingFunction,
        rpc_servers: Optional[Dict[str, str]] = None,
        secretary_model: Optional[str] = None,
        confirmer: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.embedding_model = embedding_model
        self.rpc_registry = rpc_servers or {}
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        self.collection = self.client.get_or_create_collection(
            name="tool_inventory",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.embedding_model,
        )
        self.secretary_model = secretary_model or SECRETARY_MODEL
        # Human-in-the-loop gate for executions. Sync or async callables that
        # take a full-metadata summary dict and return a truthy value to approve.
        self.confirmer = confirmer or _cli_confirmer
        self.secretary = self._init_secretary_agent()

    def _init_secretary_agent(self, model: Optional[Any] = None):
        """Build the conversational tool secretary.

        One agent, one loop: search -> select -> execute -> report. The model
        reaches tools only through `search_tools` (semantic retrieval), never
        by having the registry stuffed into its context. The final answer is
        plain text; swap `model` for a test double in unit tests.
        """
        if model is None:
            from pydantic_ai.models.ollama import OllamaModel
            from pydantic_ai.providers.ollama import OllamaProvider
            model = OllamaModel(self.secretary_model, provider=OllamaProvider(base_url=OLLAMA_BASE_URL))

        toolset = FunctionToolset([
            Tool(secretary_search_tools, takes_ctx=True, name="search_tools"),
            Tool(secretary_execute_tool, takes_ctx=True, name="execute_tool", requires_approval=True),
        ])

        instructions = textwrap.dedent("""\
            You are the tool secretary of a modular security framework.

            Workflow for every request:
            1. Call `search_tools` with a short semantic description of what the user wants.
            2. Pick exactly one tool from the results; copy its `tool_id` verbatim.
            3. Call `execute_tool` with that tool_id and the arguments the request needs.
            4. Report the outcome in 1-3 short sentences, naming the tool_id and the key output.

            Rules:
            - A human operator approves every execution and is shown the full manifest first.
              If the user denies an execution, do not retry it without new instructions.
            - If no search result matches the request, say so instead of executing something unrelated.
            - Never claim a module ran unless `execute_tool` returned a result to you in this turn.
            - Arguments are forwarded to the module as `--key value`; keep values simple and explicit.
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

    @staticmethod
    def _ensure_valid_manifest(manifest: Any) -> ToolManifest:
        try:
            result = ToolManifest.from_output(manifest)
            if isinstance(result, list):
                raise ValueError("Expected a single ToolManifest, got a list")
            return result
        except ValidationError as exc:
            raise ValueError(f"Invalid ToolManifest payload: {exc}") from exc

    @staticmethod
    def _resolve_script_path(script_path: Union[str, Path]) -> Path:
        candidate = Path(script_path)
        if not candidate.is_absolute():
            candidate = (WORKSPACE_ROOT / candidate).resolve()
        candidate = candidate.resolve()

        allowed = any(
            try_path == candidate or str(candidate).startswith(str(try_path) + os.sep)
            for try_path in ALLOWED_TOOL_ROOTS
        )
        if not allowed:
            raise ValueError(f"Script path is outside the allowed workspace roots: {script_path}")
        return candidate

    async def _embed_text(self, text: str):
        """Use Ollama's native embedding endpoint for nomic-embed-text.

        pydantic_ai's OllamaModel is a chat model wrapper, not a direct embedding client.
        The embedding model must be called via the Ollama API endpoint.
        
        Derives the embed endpoint from OLLAMA_BASE_URL by stripping /v1 suffix.
        """
        if hasattr(self.embedding_model, "embed"):
            embedding = self.embedding_model.embed(text)
            return await embedding if inspect.isawaitable(embedding) else embedding

        # Strip /v1 suffix from OLLAMA_BASE_URL to get the base endpoint
        embed_base = OLLAMA_BASE_URL.rstrip("/")
        if embed_base.endswith("/v1"):
            embed_base = embed_base[:-3]
        
        embed_url = f"{embed_base}/api/embed"

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                embed_url,
                json={
                    "model": "nomic-embed-text",
                    "input": text,
                },
            )
            response.raise_for_status()
            payload = response.json() or {}

        if "embedding" in payload:
            return payload["embedding"]
        if "embeddings" in payload:
            embedding = payload["embeddings"]
            if isinstance(embedding, list) and embedding and isinstance(embedding[0], list):
                return embedding[0]
            return embedding

        raise ValueError(f"Unexpected Ollama embedding response: {payload}")

    async def register_tool(self, manifest: Union[ToolManifest, List[ToolManifest]]):
        manifests = manifest if isinstance(manifest, list) else [manifest]
        results = []
        for m in manifests:
            m = self._ensure_valid_manifest(m)

            if m.transport == TransportType.LOCAL_FILE:
                m.implementation_path = str(self._resolve_script_path(m.implementation_path))
            existing = self.collection.get(ids=[m.module_id], include=[])
            if existing and existing.get("ids"):
                continue

            vector = await self._embed_text(m.internal_semantic_capability)
            self.collection.add(
                ids=[m.module_id],
                embeddings=[vector],
                metadatas=[{
                    "internal_semantics": m.internal_semantics,
                    "external_description": m.external_sanitized_description,
                    "implementation_path": m.implementation_path,
                    "transport": m.transport.value,
                }],
                documents=[m.internal_semantic_capability]
            )
            results.append(m.module_id)
        return results

    def discover_local_tools(self, root: Optional[str | Path] = None, include_tests: bool = False):
        """Discover Python modules in the workspace and convert them into ToolManifest objects.

        This is intentionally simple: it is a startup scanner, not a full plugin system.
        It avoids hardcoded dispatch by registering local modules based on repo layout.
        Skips venv, .venv, node_modules, and other common non-project directories.
        """
        target_root = Path(root) if root is not None else WORKSPACE_ROOT
        target_root = target_root.resolve()

        # Directories to skip (virtual environments, node packages, etc.)
        skip_dirs = {"venv", ".venv", "env", "ENV", "node_modules", ".git", "__pycache__", ".pytest_cache", ".tox", "build", "dist"}

        manifests = []
        for base in ALLOWED_TOOL_ROOTS:
            if not base.exists():
                continue
            for path in sorted(base.rglob("*.py")):
                # Skip if any path component is in skip_dirs
                if any(part in skip_dirs for part in path.parts):
                    continue
                if not path.is_file():
                    continue
                if path.name.startswith("__") and path.name.endswith("__.py"):
                    continue
                if path.name == "daharness.py":
                    continue
                if not include_tests and "tests" in path.parts:
                    continue

                rel_path = path.relative_to(WORKSPACE_ROOT)
                module_id = f"local:{rel_path.as_posix()}"
                semantic = " ".join(part for part in rel_path.with_suffix("").parts if part not in {"__init__"})
                description = f"Local tool module: {rel_path.stem.replace('_', ' ')}"
                manifests.append(
                    ToolManifest(
                        module_id=module_id,
                        internal_semantic_capability=semantic or rel_path.stem,
                        external_sanitized_description=description,
                        parameters={},
                        implementation_path=rel_path.as_posix(),
                        internal_semantics=f"local repository module: {semantic or rel_path.stem}",
                        transport=TransportType.LOCAL_FILE,
                    )
                )

        return manifests

    async def bootstrap_registry(self, root: Optional[str | Path] = None, include_tests: bool = False):
        """Discover local tools and ingest tools from known MCP servers."""
        # Discover and register local tools
        discovered = self.discover_local_tools(root=root, include_tests=include_tests)
        print(f"[bootstrap] Discovered {len(discovered)} Python modules to embed and register...")
        for i, manifest in enumerate(discovered, 1):
            print(f"[{i}/{len(discovered)}] Registering {manifest.module_id}...")
            await self.register_tool(manifest)
        total = len(self.collection.get(include=[]).get("ids", []))
        print(f"[bootstrap] Complete! Total tools registered: {total}")
        return total
    async def find_tool_by_id(self, tool_id: str) -> Optional[ToolManifest]:
        """Retrieve a tool manifest by its module_id."""
        if not tool_id or not tool_id.strip():
            return None

        existing = self.collection.get(ids=[tool_id], include=["metadatas", "documents"])
        if not existing or not existing.get("ids"):
            return None

        meta = existing["metadatas"][0]
        doc = existing["documents"][0]

        return ToolManifest(
            module_id=tool_id,
            internal_semantic_capability=doc,
            external_sanitized_description=str(meta.get("external_description", "")),
            implementation_path=str(meta.get("implementation_path", "")),
            parameters={},
            internal_semantics=str(meta.get("internal_semantics", "")),
            transport=TransportType(meta.get("transport", TransportType.LOCAL_FILE.value)),
        )
    async def find_tools(self, user_intent: str, top_k: int = 5) -> List[ToolManifest]:
        """Semantic search using ChromaDB's HNSW index, returning up to `top_k` manifests."""
        if not user_intent or not user_intent.strip():
            return []

        intent_vector = await self._embed_text(user_intent)

        results = self.collection.query(
            query_embeddings=[intent_vector],
            n_results=max(1, top_k),
        )
        if not results or not results.get('ids') or not results['ids'][0]:
            return []

        ids = results['ids'][0]
        metadatas = results.get('metadatas') or []
        documents = results.get('documents') or []
        if not metadatas or not documents or not metadatas[0] or not documents[0]:
            return []

        manifests: List[ToolManifest] = []
        for i, (best_id, meta, doc) in enumerate(zip(ids, metadatas[0], documents[0]), 1):
            if not meta or not doc:
                continue
            logger.info(
                f"[TOOL_ACTIVATION] Intent: '{user_intent}' -> Match {i}/{len(ids)}: {best_id} | Capability: {doc}"
            )
            manifests.append(
                ToolManifest(
                    module_id=best_id,
                    internal_semantic_capability=doc,
                    external_sanitized_description=str(meta.get("external_description", "")),
                    implementation_path=str(meta.get("implementation_path", "")),
                    parameters={},
                    internal_semantics=str(meta.get("internal_semantics", "")),
                    transport=TransportType(meta.get("transport", TransportType.LOCAL_FILE.value)),
                )
            )
        return manifests

    async def find_best_tool(self, user_intent: str, top_k=1):
        """Best single match for an intent (kept for the direct-dispatch API path)."""
        manifests = await self.find_tools(user_intent, top_k=top_k)
        return manifests[0] if manifests else None

    def describe_manifest(self, manifest: ToolManifest) -> Dict[str, Any]:
        """Full (non-sanitized) view of a manifest for the secretary and the confirmer."""
        return {
            "tool_id": manifest.module_id,
            "capability": manifest.internal_semantic_capability,
            "description": manifest.external_sanitized_description,
            "implementation_path": manifest.implementation_path,
            "transport": manifest.transport.value,
            "parameters": manifest.parameters,
            "internal_semantics": manifest.internal_semantics,
        }

    def validate_arguments(self, manifest: ToolManifest, arguments: Dict[str, Any]) -> List[str]:
        """Soft-check arguments against the manifest's JSON-schema-ish parameters."""
        warnings: List[str] = []
        params = manifest.parameters or {}
        if isinstance(params, dict):
            properties = params.get("properties")
            required = params.get("required")
            if isinstance(properties, dict):
                unknown = [key for key in arguments if key not in properties]
                if unknown:
                    warnings.append(f"Arguments not in the module schema: {unknown}")
            if isinstance(required, list):
                missing = [key for key in required if key not in arguments]
                if missing:
                    warnings.append(f"Missing required arguments: {missing}")
        if warnings:
            logger.info(f"[TOOL_ARGS_WARN] {manifest.module_id}: {warnings}")
        return warnings

    def get_sanitized_view(self, manifest: ToolManifest):
        """Returns only the opaque ID and the boring description for the main model."""
        return {
            "id": manifest.module_id,
            "description": manifest.external_sanitized_description
        }

    async def execute_tool(self, manifest: ToolManifest, arguments: dict):
        manifest = self._ensure_valid_manifest(manifest)

        # LOGGING: Record actual execution start
        logger.info(f"[TOOL_EXECUTE] Executing Tool ID: {manifest.module_id} | Path: {manifest.implementation_path} | Args: {arguments}")

        if manifest.transport == TransportType.LOCAL_FILE:
            # If this is an MCP wrapper, log it
            if "MCP wrapper" in manifest.internal_semantics:
                print(f"[MCP] Executing MCP wrapper: {manifest.module_id}")
            return await self._execute_local_script(manifest.implementation_path, arguments)

        raise ValueError(f"Unsupported transport type: {manifest.transport}")

    def _pending_call_summary(self, call: Any, deps: SecretaryDeps) -> Dict[str, Any]:
        """Full-metadata summary of a pending execution for the human confirmer."""
        args = _parse_tool_args(call.args)
        tool_id = str(args.get("tool_id", "")) if isinstance(args, dict) else ""
        manifest = deps.get_surfaced(tool_id)
        if manifest is not None:
            base = self.describe_manifest(manifest)
        else:
            base = {"manifest": "NOT FOUND in this conversation's search results - deny unless you can verify it"}
        return {"tool_name": call.tool_name, **base, "arguments": args}

    async def run_secretary(
        self,
        user_prompt: str,
        *,
        deps: Optional[SecretaryDeps] = None,
        message_history: Optional[List[Any]] = None,
        confirmer: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        """Run one conversation turn through the secretary agent.

        The agent searches the registry, selects a module and executes it.
        Executions are gated on human approval: when the agent calls
        `execute_tool`, the run pauses with `DeferredToolRequests`, the
        confirmer is shown the full manifest + arguments, and the run resumes
        with the approve/deny decision. Pass the same `deps` instance plus the
        previous `result.all_messages()` back in to continue a conversation.
        """
        confirmer = confirmer or self.confirmer
        deps = deps or SecretaryDeps(registry=self)

        result = await self.secretary.run(user_prompt, deps=deps, message_history=message_history)

        rounds = 0
        while isinstance(result.output, DeferredToolRequests):
            rounds += 1
            if rounds > SECRETARY_MAX_APPROVAL_ROUNDS:
                raise RuntimeError(
                    f"Secretary exceeded {SECRETARY_MAX_APPROVAL_ROUNDS} approval rounds; aborting run."
                )

            approvals: Dict[str, Any] = {}
            for call in result.output.approvals:
                summary = self._pending_call_summary(call, deps)
                logger.info(f"[TOOL_CONFIRM] Requesting approval: {json.dumps(summary, default=str)}")
                approved = await _run_confirmer(confirmer, summary)
                logger.info(
                    f"[TOOL_CONFIRM] Decision for {call.tool_call_id}: {'approved' if approved else 'denied'}"
                )
                if approved:
                    approvals[call.tool_call_id] = ToolApproved()
                else:
                    approvals[call.tool_call_id] = ToolDenied(
                        message="The user denied this execution. Do not retry it without new instructions."
                    )

            result = await self.secretary.run(
                message_history=result.all_messages(),
                deferred_tool_results=result.output.build_results(approvals=approvals),
                deps=deps,
            )

        return result

    async def _execute_local_script(self, script_path: str, arguments: dict):
        """
        Execute a local Python script or module.
        """
        try:
            resolved_path = self._resolve_script_path(script_path)
            arg_list = []
            for key, value in (arguments or {}).items():
                if isinstance(value, (dict, list, tuple, bool)):
                    arg_list.extend([f"--{key}", json.dumps(value)])
                else:
                    arg_list.extend([f"--{key}", str(value)])

            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, str(resolved_path), *arg_list],
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "status": "Success" if result.returncode == 0 else "Failed"
            }
        except subprocess.TimeoutExpired:
            return {"error": "Script execution timed out", "return_code": -1}
        except Exception as e:
            return {"error": str(e), "return_code": -1}


async def _chat(registry: "ToolRegistry") -> None:
    """Interactive conversation with the secretary; one session, full history."""
    deps = SecretaryDeps(registry=registry)
    history = None
    print("[chat] Secretary ready. Type 'exit' to quit.")
    while True:
        try:
            user_input = await asyncio.to_thread(input, "\nyou> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user_input.strip().lower() in {"exit", "quit"}:
            break
        if not user_input.strip():
            continue
        try:
            result = await registry.run_secretary(user_input.strip(), deps=deps, message_history=history)
        except Exception as exc:
            print(f"[chat] Error: {exc}")
            continue
        history = result.all_messages()
        print(f"secretary> {result.output}")


if __name__ == "__main__":
    # we need a startup script to scan the repo for its tools and register them into the vector database for the main model to use. 
    import sys
    try:
        registry = ToolRegistry(embedding_model=OllamaEmbeddingFunction())
        
        # Clear the collection if --clear flag is passed
        if "--clear" in sys.argv:
            print("[bootstrap] Clearing collection 'tool_inventory'...")
            # Get all IDs and delete them
            existing = registry.collection.get()
            if existing["ids"]:
                registry.collection.delete(ids=existing["ids"])
                print(f"[bootstrap] Deleted {len(existing['ids'])} tools from collection.")
            else:
                print("[bootstrap] Collection already empty.")
        
        if "--chat" in sys.argv:
            asyncio.run(_chat(registry))
        else:
            asyncio.run(registry.bootstrap_registry())
    except KeyboardInterrupt:
        print("\n[bootstrap] Interrupted by user.")
    except Exception as e:
        print(f"[bootstrap] Error: {e}")
        import traceback
        traceback.print_exc()


