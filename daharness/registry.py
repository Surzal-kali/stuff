import os
import json
import logging
import asyncio
import httpx
import chromadb
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from chromadb.utils import embedding_functions
from .models import ToolManifest
from constants import TransportType

logger = logging.getLogger(__name__)

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

class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __init__(self, model_name: str = "nomic-embed-text", base_url: str = OLLAMA_BASE_URL):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/v1")
        self.embed_url = f"{self.base_url}/api/embed"

    async def __call__(self, texts: List[str]) -> List[List[float]]:
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

    def name(self) -> str:
        return self.model_name

class ToolRegistry:
    def __init__(self, embedding_model: OllamaEmbeddingFunction):
        self.embedding_model = embedding_model
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        self.collection = self.client.get_or_create_collection(
            name="tool_inventory",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.embedding_model,
        )

    async def _embed_text(self, text: str):
        # Implementation from daharness.py
        embed_base = OLLAMA_BASE_URL.rstrip("/")
        if embed_base.endswith("/v1"):
            embed_base = embed_base[:-3]
        embed_url = f"{embed_base}/api/embed"
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(embed_url, json={"model": "nomic-embed-text", "input": text})
            response.raise_for_status()
            payload = response.json() or {}
        if "embedding" in payload: return payload["embedding"]
        if "embeddings" in payload:
            embedding = payload["embeddings"]
            return embedding[0] if isinstance(embedding, list) and embedding and isinstance(embedding[0], list) else embedding
        raise ValueError(f"Unexpected Ollama embedding response: {payload}")

    async def register_tool(self, manifest: Union[ToolManifest, List[ToolManifest]]):
        manifests = manifest if isinstance(manifest, list) else [manifest]
        results = []
        for m in manifests:
            m = self._ensure_valid_manifest(m)
            if m.transport == TransportType.LOCAL_FILE:
                m.implementation_path = str(self._resolve_script_path(m.implementation_path))
            
            existing = self.collection.get(ids=[m.module_id], include=["documents", "metadatas"])
            if existing and existing.get("ids"):
                old_doc = (existing.get("documents") or [""])[0] or ""
                old_meta = (existing.get("metadatas") or [{}])[0] or {}
                new_meta_json = json.dumps(m.parameters or {})
                if (old_doc == m.internal_semantic_capability and 
                    str(old_meta.get("implementation_path", "")) == m.implementation_path and 
                    old_meta.get("transport") == m.transport.value and 
                    old_meta.get("parameters_json") == new_meta_json):
                    continue
                self.collection.delete(ids=[m.module_id])

            vector = await self._embed_text(m.internal_semantic_capability)
            self.collection.add(
                ids=[m.module_id],
                embeddings=[vector],
                metadatas=[{
                    "internal_semantics": m.internal_semantics,
                    "external_description": m.external_sanitized_description,
                    "implementation_path": m.implementation_path,
                    "transport": m.transport.value,
                    "parameters_json": json.dumps(m.parameters or {}),
                }],
                documents=[m.internal_semantic_capability],
            )
            results.append(m.module_id)
        return results

    @staticmethod
    def _ensure_valid_manifest(manifest: Any) -> ToolManifest:
        try:
            result = ToolManifest.from_output(manifest)
            if isinstance(result, list): raise ValueError("Expected a single ToolManifest, got a list")
            return result
        except Exception as exc:
            raise ValueError(f"Invalid ToolManifest payload: {exc}") from exc

    @staticmethod
    def _resolve_script_path(script_path: Union[str, Path]) -> Path:
        candidate = Path(script_path)
        if not candidate.is_absolute():
            candidate = (WORKSPACE_ROOT / candidate).resolve()
        candidate = candidate.resolve()
        if not any(try_path == candidate or str(candidate).startswith(str(try_path) + os.sep) for try_path in ALLOWED_TOOL_ROOTS):
            raise ValueError(f"Script path is outside the allowed workspace roots: {script_path}")
        return candidate

    async def find_tools(self, user_intent: str, top_k: int = 5) -> List[ToolManifest]:
        if not user_intent or not user_intent.strip(): return []
        intent_vector = await self._embed_text(user_intent)
        results = self.collection.query(query_embeddings=[intent_vector], n_results=max(1, top_k))
        if not results or not results.get("ids") or not results["ids"][0]: return []
        
        ids, metadatas, documents = results["ids"][0], results.get("metadatas")[0], results.get("documents")[0]
        manifests = []
        for best_id, meta, doc in zip(ids, metadatas, documents):
            manifests.append(ToolManifest(
                module_id=best_id,
                internal_semantic_capability=doc,
                external_sanitized_description=str(meta.get("external_description", "")),
                implementation_path=str(meta.get("implementation_path", "")),
                parameters=self._safe_parse_params(meta.get("parameters_json")),
                internal_semantics=str(meta.get("internal_semantics", "")),
                transport=TransportType(meta.get("transport", TransportType.LOCAL_FILE.value)),
            ))
        return manifests

    def _safe_parse_params(self, raw: Any) -> dict:
        try:
            parsed = json.loads(raw) if raw else {}
            return parsed if isinstance(parsed, dict) else {}
        except: return {}

    async def find_tool_by_id(self, tool_id: str) -> Optional[ToolManifest]:
        if not tool_id or not tool_id.strip(): return None
        existing = self.collection.get(ids=[tool_id], include=["metadatas", "documents"])
        if not existing or not existing.get("ids"): return None
        meta, doc = (existing.get("metadatas") or [{}])[0], (existing.get("documents") or [{}])[0]
        return ToolManifest(
            module_id=tool_id,
            internal_semantic_capability=str(doc),
            external_sanitized_description=str(meta.get("external_description", "")),
            implementation_path=str(meta.get("implementation_path", "")),
            parameters=self._safe_parse_params(meta.get("parameters_json", "{}")),
            internal_semantics=str(meta.get("internal_semantics", "")),
            transport=TransportType(meta.get("transport", TransportType.LOCAL_FILE.value)),
        )
