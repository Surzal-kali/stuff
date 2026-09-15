#!/usr/bin/env python3
"""Minimal API gateway startup for the containerized workbench.

Starts the framework REST + MCP API gateway without the full bootstrap
(no ZAP, no MSF, no interactive secretary chat loop). The Brain sidecar
runs as a separate process started by the entrypoint.
"""
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FRAMEWORK_ROOT))
os.chdir(str(FRAMEWORK_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("gateway")


def wait_for_chromadb(timeout=90):
    """Retry ChromaDB connection until it is reachable."""
    import chromadb

    host = os.getenv("CHROMA_HOST", "chromadb")
    port = int(os.getenv("CHROMA_PORT", "8000"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            client = chromadb.HttpClient(host=host, port=port)
            client.heartbeat()
            logger.info("ChromaDB connected at %s:%d", host, port)
            return
        except Exception as e:
            logger.info("Waiting for ChromaDB at %s:%d ... %s", host, port, e)
            time.sleep(2)
    raise RuntimeError(
        f"ChromaDB not reachable at {host}:{port} after {timeout}s"
    )


async def main():
    from daharness.registry import ToolRegistry, OllamaEmbeddingFunction
    from memories import MemoryService
    from api_gateway import APIGateway
    import uvicorn

    wait_for_chromadb()

    embedding_function = OllamaEmbeddingFunction(model_name="nomic-embed-text")
    tool_registry = ToolRegistry(
        embedding_model=embedding_function,
        rpc_servers={},
    )
    memory_service = MemoryService(
        storage_path=str(FRAMEWORK_ROOT / ".memory" / "chroma")
    )
    gateway = APIGateway(tool_registry, memory_service)

    config = uvicorn.Config(
        gateway.app,
        host="0.0.0.0",
        port=6000,
        log_level="info",
    )
    server = uvicorn.Server(config)
    logger.info("API gateway starting on 0.0.0.0:6000")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
