from __future__ import annotations

from pathlib import Path
from typing import Any

import chromadb


class MemoryService:
    """Persistent, namespaced vector memory for cross-harness recall."""

    def __init__(self, storage_path: str = ".memory/chroma"):
        self.storage_path = str(Path(storage_path))
        self.client = chromadb.PersistentClient(path=self.storage_path)
        self._collections: dict[str, Any] = {}

    def _namespace_name(self, namespace: str) -> str:
        namespace = str(namespace).strip()
        if not namespace:
            raise ValueError("namespace must be a non-empty string")
        return f"memory_{namespace}"

    def _get_collection(self, namespace: str):
        name = self._namespace_name(namespace)
        if name not in self._collections:
            self._collections[name] = self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collections[name]

    def list_namespaces(self) -> list[str]:
        """Return all namespaces that currently have a collection."""
        collections = self.client.list_collections()
        names = []
        for collection in collections:
            name = collection.name
            if name.startswith("memory_"):
                names.append(name.replace("memory_", "", 1))
        return sorted(names)

    def remember(
        self,
        namespace: str,
        memory_id: str,
        text: str,
        embedding: list[float],
        **metadata: Any,
    ) -> str:
        collection = self._get_collection(namespace)
        collection.upsert(
            ids=[str(memory_id)],
            documents=[str(text)],
            embeddings=[list(embedding)],
            metadatas=[dict(metadata)],
        )
        return str(memory_id)

    def search(self, namespace: str, query_text: str, limit: int = 5) -> list[dict[str, Any]]:
        """Simple keyword-style search over stored document text within a namespace."""
        collection = self._get_collection(namespace)
        query = str(query_text).strip()
        if not query:
            return []

        results = collection.get(include=["documents", "metadatas"])
        ids = results.get("ids", [])
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])

        hits: list[dict[str, Any]] = []
        for index, memory_id in enumerate(ids):
            document = documents[index] if index < len(documents) else ""
            if query.lower() in document.lower():
                hits.append(
                    {
                        "id": memory_id,
                        "document": document,
                        "metadata": metadatas[index] if index < len(metadatas) else {},
                    }
                )
            if len(hits) >= max(1, int(limit)):
                break
        return hits

    def recall(
        self,
        namespace: str,
        query_embedding: list[float],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        collection = self._get_collection(namespace)
        results = collection.query(
            query_embeddings=[list(query_embedding)],
            n_results=max(1, int(limit)),
            include=["documents", "metadatas", "distances"],
        )

        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        hits: list[dict[str, Any]] = []
        for index, memory_id in enumerate(ids):
            hits.append(
                {
                    "id": memory_id,
                    "document": documents[index] if index < len(documents) else None,
                    "metadata": metadatas[index] if index < len(metadatas) else {},
                    "distance": distances[index] if index < len(distances) else None,
                }
            )
        return hits

    def get(self, namespace: str, memory_id: str) -> dict[str, Any] | None:
        collection = self._get_collection(namespace)
        result = collection.get(ids=[str(memory_id)], include=["documents", "metadatas", "embeddings"])
        ids = result.get("ids", [])
        if not ids or str(memory_id) not in ids:
            return None

        index = ids.index(str(memory_id))
        return {
            "id": str(memory_id),
            "document": result.get("documents", [None])[index],
            "metadata": result.get("metadatas", [{}])[index],
            "embedding": result.get("embeddings", [None])[index],
        }

    def forget(self, namespace: str, memory_id: str) -> None:
        collection = self._get_collection(namespace)
        collection.delete(ids=[str(memory_id)])


_default_service = MemoryService()


def store_embedding(key: str, embedding: list[float], namespace: str = "shared") -> str:
    """Compatibility wrapper for storing a raw embedding under a namespaced key."""
    return _default_service.remember(
        namespace=namespace,
        memory_id=key,
        text=key,
        embedding=list(embedding),
        source="embedding",
    )


def retrieve_embedding(key: str, namespace: str = "shared") -> tuple[list[float] | None, str | None]:
    """Compatibility wrapper returning the stored embedding and id for a key."""
    result = _default_service.get(namespace=namespace, memory_id=key)
    if result is None:
        return None, None
    return result.get("embedding"), result.get("id")


def store_id(key: str, id_value: str, namespace: str = "shared") -> str:
    """Compatibility wrapper for storing a key-to-id mapping in a namespace."""
    return _default_service.remember(
        namespace=namespace,
        memory_id=str(id_value),
        text=str(key),
        embedding=[0.0],
        source="id",
        key=str(key),
    )


def retrieve_id(key: str, namespace: str = "shared") -> str:
    """Compatibility wrapper for retrieving the id assigned to a key."""
    collection = _default_service._get_collection(namespace)
    results = collection.get(where={"key": str(key)}, include=["ids", "metadatas"])
    ids = results.get("ids", [])
    return ids[0] if ids else ""


__all__ = [
    "MemoryService",
    "store_embedding",
    "retrieve_embedding",
    "store_id",
    "retrieve_id",
]


