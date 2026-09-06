import logging
import os
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from daharness import ToolRegistry, OllamaEmbeddingFunction

logger = logging.getLogger(__name__)


class ToolRequest(BaseModel):
    intent: str
    arguments: Optional[dict] = None

class ToolLookupRequest(BaseModel):
    tool_id: str

class MemorySearchRequest(BaseModel):
    namespace: str
    query_text: Optional[str] = None

class MemoryRecallRequest(BaseModel):
    namespace: str
    query_embedding: list
    limit: Optional[int] = 5

class APIGateway:
    def __init__(self, tool_registry: ToolRegistry, memory_service, api_key: Optional[str] = None):
        self.tool_registry = tool_registry
        self.memory_service = memory_service
        self.api_key = api_key
        self.app = FastAPI()

        # --- API key middleware -------------------------------------------------
        # If GATEWAY_API_KEY is set (either via constructor or env), every
        # request must carry a matching ``X-API-Key`` header (or
        # ``Authorization: Bearer <key>``).  When no key is configured the
        # gateway runs in open dev mode — but logs a prominent warning so the
        # operator knows it's unauthenticated.
        expected_key = self.api_key or os.getenv("GATEWAY_API_KEY")
        if expected_key:
            logger.info("[gateway] API key authentication enabled")
        else:
            logger.warning("[gateway] GATEWAY_API_KEY not set — running in unauthenticated dev mode")

        @self.app.middleware("http")
        async def verify_api_key(request: Request, call_next):
            if not expected_key:
                return await call_next(request)
            # Skip docs/health endpoints so the OpenAPI spec stays reachable.
            if request.url.path in ("/docs", "/redoc", "/openapi.json", "/health"):
                return await call_next(request)
            provided = request.headers.get("X-API-Key")
            if not provided:
                auth = request.headers.get("Authorization", "")
                if auth.lower().startswith("bearer "):
                    provided = auth[7:].strip()
            if not provided or not secrets.compare_digest(provided, expected_key):
                return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
            return await call_next(request)

        @self.app.get("/health")
        async def health():
            return {"status": "ok"}

        @self.app.post("/tools/execute")
        async def execute_tool(req: ToolRequest):
            manifest = await self.tool_registry.find_best_tool(req.intent)
            if not manifest:
                raise HTTPException(404, "No tool found for intent")
            
            execution_result = await self.tool_registry.execute_tool(manifest, req.arguments or {})
            
            # Return the result along with identifying information about the tool used
            logging.info(f"Executed tool {manifest.module_id} for intent '{req.intent}' with result: {execution_result}")
            return {
                "tool_id": manifest.module_id,
                "tool_name": manifest.external_sanitized_description,
                "result": execution_result
            }
        logging.basicConfig(level=logging.INFO)

        @self.app.post("/memory/search")
        async def search_memory(req: MemorySearchRequest):
            if not req.query_text:
                raise HTTPException(400, "query_text is required for text-based search")
            return self.memory_service.search(
                namespace=req.namespace,
                query_text=req.query_text,
            )

        @self.app.post("/memory/recall")
        async def recall_memory(req: MemoryRecallRequest):
            return self.memory_service.recall(
                namespace=req.namespace,
                query_embedding=req.query_embedding,
                limit=req.limit,
            )
async def run(loader, host="127.0.0.1", port=6000):
    # Reuse the loader's already-initialized ToolRegistry instead of building a
    # second one.  The loader's registry shares the same ChromaDB collection,
    # cached tool instances (MetasploitClient, SMBScanner, ...), and Brain
    # dispatch state that bootstrap spent startup time priming.  Constructing a
    # fresh registry here would create a parallel set of class instances and
    # silently desync state (e.g. two MetasploitClient objects fighting over
    # the same console handle).
    tool_registry = loader.vector_registry
    if tool_registry is None:
        # Fallback: if the loader failed to init its registry, construct one
        # so the gateway still boots (tools won't work, but the API is up).
        logger.warning("[gateway] loader.vector_registry is None; constructing a standalone registry")
        embedding_function = OllamaEmbeddingFunction(model_name="nomic-embed-text")
        tool_registry = ToolRegistry(
            embedding_model=embedding_function,
            rpc_servers={"metasploit": os.getenv("MCP_ENDPOINT", "http://localhost:55552")},
        )

    # Initialize MemoryService
    from memories import MemoryService
    memory_service = MemoryService(storage_path=".memory/chroma")

    # Start the API gateway
    api_gateway = APIGateway(tool_registry, memory_service)
    import uvicorn
    config = uvicorn.Config(api_gateway.app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    # Expose the server so bootstrap.stop() can request a graceful shutdown
    # (should_exit=True) instead of cancelling our task mid-lifespan, which
    # would surface as a CancelledError traceback from starlette's receive().
    loader.api_server = server
    await server.serve()