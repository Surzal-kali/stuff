import os
import json
import sys
from pathlib import Path
from pydantic import BaseModel, Field
import chromadb # Changed from weaviate
from chromadb.config import Settings
import httpx # 
from pydantic_ai import (
    Agent,
    ModelMessage,
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    ModelSettings,
    TextPart,
    UnexpectedModelBehavior,
    UserPromptPart
)
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.output import NativeOutput
from typing import List, Optional
from enum import Enum
import numpy as np # For cosine similarity
import asyncio
import subprocess

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://100.66.181.0:11434/v1")
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

class TransportType(Enum):
    """Transport mechanism for tool execution."""
    LOCAL_FILE = "local_file"
    MCP_HTTP = "mcp_http"


class ToolManifest(BaseModel):
    module_id: str = Field(..., min_length=1) # e.g., "MOD-412"
    internal_semantic_capability: str = Field(..., min_length=1) # Used for embedding/LFM lookup
    external_sanitized_description: str = Field(..., min_length=1) # What the main model sees
    parameters: dict = Field(default_factory=dict)
    implementation_path: str = Field(..., min_length=1) # e.g., "auxiliaries/smb_scanner.py"
    internal_semantics: str = Field(..., min_length=1)
    transport: TransportType = TransportType.LOCAL_FILE # Transport mechanism
    endpoint: Optional[str] = None # MCP HTTP endpoint URL
    tool_name: Optional[str] = None # Actual tool name in the implementation

    @classmethod
    def from_output(cls, payload):
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, dict):
            return cls.model_validate(payload)
        if hasattr(payload, "model_dump"):
            return cls.model_validate(payload.model_dump())
        raise TypeError(f"Unsupported ToolManifest payload: {type(payload).__name__}")


#for testing we'll bring out gemma4:12b
model = OllamaModel("gemma4:12b", provider=OllamaProvider(base_url=OLLAMA_BASE_URL))
#this will be the secretary agent that will handle the requests to the model anything that is directly tied to a module in name must be semantically "translated" back to the main model. module #1 vs module ms17_eb ya feel?

#we'll need vectors and an embedding agent to allocate the full lot of the tools

secretary_model = OllamaModel("lfm2.5-thinking:1.2b", provider=OllamaProvider(base_url=OLLAMA_BASE_URL))

agent = Agent(model, output_type=NativeOutput)

secretary = Agent(secretary_model, output_type=ToolManifest)

embeddings = OllamaModel("nomic-embed-text", provider=OllamaProvider(base_url=OLLAMA_BASE_URL))


class ToolRegistry:
    def __init__(self, embedding_model):
        self.embedding_model = embedding_model
        # Initialize ChromaDB HTTP Client
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        # Create or get the 'tool_inventory' collection
        self.collection = self.client.get_or_create_collection(name="tool_inventory")

    @staticmethod
    def _ensure_valid_manifest(manifest):
        try:
            return ToolManifest.from_output(manifest)
        except Exception as exc:
            raise ValueError(f"Invalid ToolManifest payload: {exc}") from exc

    @staticmethod
    def _resolve_script_path(script_path: str) -> Path:
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
            return await self.embedding_model.embed(text)

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

    async def register_tool(self, manifest: ToolManifest):
        """Embeds capability and stores in ChromaDB."""
        manifest = self._ensure_valid_manifest(manifest)

        if manifest.transport == TransportType.LOCAL_FILE:
            manifest.implementation_path = str(self._resolve_script_path(manifest.implementation_path))

        existing = self.collection.get(ids=[manifest.module_id], include=[])
        if existing and existing.get("ids"):
            return

        # Generate vector using your Ollama embedding model
        vector = await self._embed_text(manifest.internal_semantic_capability)

        # Chroma expects a list of IDs, documents, and embeddings
        self.collection.add(
            ids=[manifest.module_id],
            embeddings=[vector],
            metadatas=[{
                "internal_semantics": manifest.internal_semantics,
                "external_description": manifest.external_sanitized_description,
                "implementation_path": manifest.implementation_path,
                "transport": manifest.transport.value,
            }],
            documents=[manifest.internal_semantic_capability]
        )

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
        """Discover the repo and register all local tool manifests into Chroma."""
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
        """
        The Bridge: This function takes the manifest from ChromaDB 
        and routes it to the actual implementation.
        """
        manifest = self._ensure_valid_manifest(manifest)

        if manifest.transport == TransportType.LOCAL_FILE:
            # Execute local python script
            return await self._execute_local_script(manifest.implementation_path, arguments)
        
        elif manifest.transport == TransportType.MCP_HTTP:
            # Forward the call to the MCP Server
            if not manifest.endpoint or not manifest.tool_name:
                raise ValueError("endpoint and tool_name required for MCP_HTTP transport")
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{manifest.endpoint.rstrip('/')}/tools/call", 
                    json={
                        "tool_name": manifest.tool_name, # The actual function name
                        "arguments": arguments or {}
                    }
                )
                response.raise_for_status()
                return response.json()

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
                "return_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Script execution timed out", "return_code": -1}
        except Exception as e:
            return {"error": str(e), "return_code": -1}


if __name__ == "__main__":
    # we need a startup script to scan the repo for its tools and register them into the vector database for the main model to use. 
    import sys
    try:
        registry = ToolRegistry(embedding_model=embeddings)
        
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

