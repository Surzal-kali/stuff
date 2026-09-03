import os
import json
import sys
import logging
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import httpx
from pydantic import BaseModel, Field, ValidationError
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

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
            return [cls.from_output(item) for item in payload]
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

# --- Tool Registry ---
class ToolRegistry:
    def __init__(self, embedding_model: OllamaEmbeddingFunction, rpc_servers: Optional[Dict[str, str]] = None):
        self.embedding_model = embedding_model
        self.rpc_registry = rpc_servers or {}
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        self.collection = self.client.get_or_create_collection(
            name="tool_inventory",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.embedding_model,
        )
        self.secretary = self._init_secretary_agent()

    def _init_secretary_agent(self):
        from pydantic_ai import Agent
        from pydantic_ai.models.ollama import OllamaModel
        from pydantic_ai.providers.ollama import OllamaProvider
        model = OllamaModel("lfm2.5-thinking:1.2b", provider=OllamaProvider(base_url=OLLAMA_BASE_URL))
        return Agent(model, output_type=ToolManifest)

    @staticmethod
    def _ensure_valid_manifest(manifest: Any) -> ToolManifest:
        try:
            return ToolManifest.from_output(manifest)
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
            raise ValueError(f"Script path is outside allowed workspace roots: {script_path}")
        return candidate

    async def _embed_text(self, text: str):
        """Use Ollama's native embedding endpoint for nomic-embed-text.

        pydantic_ai's OllamaModel is a chat model wrapper, not a direct embedding client.
        The embedding model must be called via the Ollama API endpoint.
        
        Derives the embed endpoint from OLLAMA_BASE_URL by stripping /v1 suffix.
        """
        if hasattr(self.embedding_model, "embed"):
            return self.embedding_model.embed_query(text)

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
                embeddings=[list(vector)],
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

    async def ingest_mcp_server(self, server_url: str, server_name: str):
        """
        Connects to a running MCP server, fetches its tool list, 
        and vectorizes each tool individualy.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{server_url.rstrip('/')}/tools/list")
            response.raise_for_status()
            tools_data = response.json() or {}

        tools = tools_data.get("tools", [])
        if not isinstance(tools, list):
            raise ValueError(f"Unexpected MCP tool payload for {server_url}: {tools_data}")

        for tool in tools:
            # Use the Secretary to refine the description for the main model
            result = await secretary.run(
                f"Translate this MCP tool definition into a ToolManifest:\n{tool}"
            )
            refined_manifest = self._ensure_valid_manifest(result.output)
            if refined_manifest.implementation_path:
                refined_manifest.implementation_path = refined_manifest.implementation_path
            
            await self.register_tool(refined_manifest)

    async def find_best_tool(self, user_intent: str, top_k=1):
        """Semantic search using ChromaDB's HNSW index."""
        if not user_intent or not user_intent.strip():
            return None

        intent_vector = await self._embed_text(user_intent)

        # Query the collection
        results = self.collection.query(
            query_embeddings=[intent_vector],
            n_results=top_k
        )

        # Fix: Ensure results is not None and contains data before subscripting
        if not results or not results.get('ids') or not results['ids'][0]:
            return None

        # Extract data from the first match
        best_id = results['ids'][0][0]
        metadatas = results.get('metadatas')
        documents = results.get('documents')
        
        if not metadatas or not documents or not metadatas[0] or not documents[0]:
            return None
            
        meta = metadatas[0][0]
        doc = documents[0][0]

        # LOGGING: Record the tool being selected for the given intent
        logger.info(f"[TOOL_ACTIVATION] Intent: '{user_intent}' -> Selected Tool ID: {best_id} | Capability: {doc}")

        # Fix: Cast metadata values to str to satisfy ToolManifest type requirements
        return ToolManifest(
            module_id=best_id,
            internal_semantic_capability=doc,
            external_sanitized_description=str(meta.get("external_description", "")),
            implementation_path=str(meta.get("implementation_path", "")),
            parameters={},
            internal_semantics=str(meta.get("internal_semantics", "")),
            transport=TransportType(meta.get("transport", TransportType.LOCAL_FILE.value)),
        )

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
        
        asyncio.run(registry.bootstrap_registry())
    except KeyboardInterrupt:
        print("\n[bootstrap] Interrupted by user.")
    except Exception as e:
        print(f"[bootstrap] Error: {e}")
        import traceback
        traceback.print_exc()


