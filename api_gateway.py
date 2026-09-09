import asyncio
import json
import logging
import os
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, Optional
from starlette.routing import Route

# MCP transport (low-level server + streamable-HTTP session manager).  The
# low-level ``Server`` is used on purpose: it advertises an explicit
# ``inputSchema`` per tool and hands the raw ``arguments`` dict straight to
# our dispatcher, so we can mirror the existing REST entrypoints without the
# function-signature inference that ``mcp.server.fastmcp.FastMCP`` would do.
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
import mcp.types as mcp_types


class _MCPEndpoint:
    """Tiny ASGI adapter around the session manager's request handler.

    ``StreamableHTTPSessionManager.handle_request`` is a *bound method*, which
    Starlette would otherwise treat as an HTTP endpoint (``func(request)``)
    rather than an ASGI app.  Wrapping it in a class instance makes Starlette
    recognise it as a plain ASGI app, so a ``Route`` (exact path, all HTTP
    methods) can serve ``/mcp`` directly — no trailing-slash ``307`` redirect
    like ``app.mount("/mcp", ...)`` would produce.
    """

    def __init__(self, session_manager: StreamableHTTPSessionManager):
        self._sm = session_manager

    async def __call__(self, scope, receive, send) -> None:
        await self._sm.handle_request(scope, receive, send)

from daharness import ToolRegistry, OllamaEmbeddingFunction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models shared by the REST endpoints and the MCP tool wrappers.
# ---------------------------------------------------------------------------
class ToolRequest(BaseModel):
    intent: str
    arguments: Optional[dict] = None
    # agent_id doubles as the Brain session id and scopes memory reads/writes.
    # Must be a TOP-LEVEL request field, NOT a tool argument (concurrent MCP
    # clients each pass their own; tool schemas stay clean).
    agent_id: Optional[str] = None

class ToolLookupRequest(BaseModel):
    tool_id: str

class MemorySearchRequest(BaseModel):
    namespace: str
    query_text: Optional[str] = None
    agent_id: Optional[str] = None

class MemoryRecallRequest(BaseModel):
    namespace: str
    query_embedding: list
    limit: Optional[int] = 5
    agent_id: Optional[str] = None


# Input schemas advertised over MCP — kept in sync with the models above so a
# tool/call and the matching REST endpoint accept exactly the same payload.
_MCP_TOOL_EXECUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "intent": {"type": "string"},
        "arguments": {"type": "object"},
        "agent_id": {
            "type": "string",
            "description": "Identity of the running model/agent. Used as the Brain session id so concurrent agents get isolated tool state (e.g. separate msfconsole handles). Omit to use the shared default session.",
        },
    },
    "required": ["intent"],
}
_MCP_MEMORY_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "namespace": {"type": "string"},
        "query_text": {"type": "string"},
        "agent_id": {"type": "string", "description": "Scope to one running model's memories; omit for the shared pool."},
    },
    "required": ["namespace", "query_text"],
}
_MCP_MEMORY_RECALL_SCHEMA = {
    "type": "object",
    "properties": {
        "namespace": {"type": "string"},
        "query_embedding": {"type": "array", "items": {"type": "number"}},
        "limit": {"type": "integer", "default": 5},
        "agent_id": {"type": "string", "description": "Scope to one running model's memories; omit for the shared pool."},
    },
    "required": ["namespace", "query_embedding"],
}

# Tool names exposed over MCP.  These wrap the same operations the REST
# entrypoints perform — the gateway is now an MCP wrapper around the same
# simple ``tools/execute`` + memory operations, not a replacement for them.
TOOL_EXECUTE = "tools_execute"
MEMORY_SEARCH = "memory_search"
MEMORY_RECALL = "memory_recall"


class APIGateway:
    def __init__(self, tool_registry: ToolRegistry, memory_service, api_key: Optional[str] = None):
        self.tool_registry = tool_registry
        self.memory_service = memory_service
        self.api_key = api_key

        # --- MCP server + transport ------------------------------------------
        # One low-level MCP server exposes the framework's operations as MCP
        # tools; the streamable-HTTP session manager turns it into an ASGI
        # app that we mount on the *same* FastAPI app as the REST routes, so
        # REST callers and MCP clients hit the identical dispatch logic.
        self.mcp_server = Server("daharness")
        self._register_mcp_handlers()
        self.session_manager = StreamableHTTPSessionManager(app=self.mcp_server)

        async def lifespan(app: FastAPI):
            # The session manager owns the per-connection MCP sessions; it must
            # be started for the lifetime of the app.  Running it here (rather
            # than as the mounted app's own lifespan, which Starlette does not
            # propagate to mounts) keeps every connection's state alive for as
            # long as uvicorn is serving.
            async with self.session_manager.run():
                yield

        self.app = FastAPI(lifespan=lifespan)

        # --- API key middleware -------------------------------------------------
        # If GATEWAY_API_KEY is set (either via constructor or env), every
        # request must carry a matching ``X-API-Key`` header (or
        # ``Authorization: Bearer <key>``).  When no key is configured the
        # gateway runs in open dev mode — but logs a prominent warning so the
        # operator knows it's unauthenticated.  This gates the REST routes AND
        # the mounted MCP endpoint at ``/mcp``.
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

        # --- REST entrypoints (unchanged) ------------------------------------
        @self.app.get("/health")
        async def health():
            return {"status": "ok"}

        @self.app.post("/tools/execute")
        async def execute_tool(req: ToolRequest):
            manifest = await self.tool_registry.find_best_tool(req.intent)
            if not manifest:
                raise HTTPException(404, "No tool found for intent")

            # agent_id doubles as the Brain session id, so each identified
            # agent gets its own isolated tool state on the sidecar; omitted
            # falls back to the shared default session ("0").
            execution_result = await self.tool_registry.execute_tool(
                manifest, req.arguments or {}, session_id=req.agent_id or "0"
            )

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
            # ChromaDB calls are synchronous and would block the event loop
            # (and every concurrent MCP session / REST request) for the duration
            # of the query; run them in a worker thread instead.
            return await asyncio.to_thread(
                self.memory_service.search,
                namespace=req.namespace,
                query_text=req.query_text,
                agent_id=req.agent_id,
            )

        @self.app.post("/memory/recall")
        async def recall_memory(req: MemoryRecallRequest):
            return await asyncio.to_thread(
                self.memory_service.recall,
                namespace=req.namespace,
                query_embedding=req.query_embedding,
                limit=req.limit,
                agent_id=req.agent_id,
            )

        # --- MCP transport route --------------------------------------------
        # Serve the streamable-HTTP ASGI app at exactly /mcp via a Route (not
        # ``app.mount``).  Mount would 307-redirect /mcp -> /mcp/ and break MCP
        # clients that don't follow redirects; a Route on the ASGI adapter
        # above serves /mcp directly for all methods.  The API-key middleware
        # still wraps the whole router, so /mcp is gated by the same key as
        # the REST routes.  MCP clients connect here and use tools/list +
        # tools/call; the handlers route to the exact same registry/memory
        # code the REST endpoints use.
        self.app.router.routes.append(Route("/mcp", _MCPEndpoint(self.session_manager)))

    # --- MCP handlers ---------------------------------------------------------
    def _register_mcp_handlers(self) -> None:
        server = self.mcp_server

        @server.list_tools()
        async def list_tools() -> list[mcp_types.Tool]:
            return [
                mcp_types.Tool(
                    name=TOOL_EXECUTE,
                    description=(
                        "Resolve a natural-language intent to the best matching "
                        "tool and execute it. Mirrors POST /tools/execute."
                    ),
                    inputSchema=_MCP_TOOL_EXECUTE_SCHEMA,
                ),
                mcp_types.Tool(
                    name=MEMORY_SEARCH,
                    description=(
                        "Search a memory namespace by text query. "
                        "Mirrors POST /memory/search."
                    ),
                    inputSchema=_MCP_MEMORY_SEARCH_SCHEMA,
                ),
                mcp_types.Tool(
                    name=MEMORY_RECALL,
                    description=(
                        "Recall memories from a namespace by embedding vector. "
                        "Mirrors POST /memory/recall."
                    ),
                    inputSchema=_MCP_MEMORY_RECALL_SCHEMA,
                ),
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict) -> Any:
            # Every branch dispatches to the same code the REST handlers call,
            # so REST and MCP stay behaviourally identical.
            try:
                if name == TOOL_EXECUTE:
                    intent = arguments.get("intent")
                    if not intent:
                        return self._error(f"{TOOL_EXECUTE}: 'intent' is required")
                    manifest = await self.tool_registry.find_best_tool(intent)
                    if not manifest:
                        return self._error(f"No tool found for intent: {intent}")
                    tool_args = arguments.get("arguments") or {}
                    # agent_id -> Brain session id for per-agent isolation.
                    session_id = arguments.get("agent_id") or "0"
                    result = await self.tool_registry.execute_tool(
                        manifest, tool_args, session_id=session_id
                    )
                    logger.info(
                        "MCP executed tool %s for intent '%s' (session=%s) with result: %s",
                        manifest.module_id, intent, session_id, result,
                    )
                    payload = {
                        "tool_id": manifest.module_id,
                        "tool_name": manifest.external_sanitized_description,
                        "result": result,
                    }
                    return [mcp_types.TextContent(type="text", text=json.dumps(payload, default=str))]

                if name == MEMORY_SEARCH:
                    namespace = arguments.get("namespace")
                    query_text = arguments.get("query_text")
                    if not namespace:
                        return self._error(f"{MEMORY_SEARCH}: 'namespace' is required")
                    if not query_text:
                        return self._error(f"{MEMORY_SEARCH}: 'query_text' is required for text-based search")
                    agent_id = arguments.get("agent_id")
                    # Run the blocking ChromaDB query off the event loop.
                    result = await asyncio.to_thread(
                        self.memory_service.search,
                        namespace=namespace, query_text=query_text, agent_id=agent_id,
                    )
                    return [mcp_types.TextContent(type="text", text=json.dumps(result, default=str))]

                if name == MEMORY_RECALL:
                    namespace = arguments.get("namespace")
                    query_embedding = arguments.get("query_embedding")
                    if not namespace:
                        return self._error(f"{MEMORY_RECALL}: 'namespace' is required")
                    if not query_embedding:
                        return self._error(f"{MEMORY_RECALL}: 'query_embedding' is required")
                    limit = arguments.get("limit", 5)
                    agent_id = arguments.get("agent_id")
                    result = await asyncio.to_thread(
                        self.memory_service.recall,
                        namespace=namespace,
                        query_embedding=query_embedding,
                        limit=limit,
                        agent_id=agent_id,
                    )
                    return [mcp_types.TextContent(type="text", text=json.dumps(result, default=str))]

                return self._error(f"Unknown MCP tool: {name}")
            except Exception as exc:  # noqa: BLE001 - surface to the MCP client
                logger.error("[gateway] MCP call_tool '%s' failed: %s", name, exc, exc_info=True)
                return self._error(f"{name}: {exc}")

    @staticmethod
    def _error(message: str) -> mcp_types.CallToolResult:
        """Build an MCP CallToolResult flagged as an error."""
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=message)],
            isError=True,
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
    # The MCP session manager is started/stopped via the FastAPI lifespan, so
    # uvicorn's clean shutdown also winds down every live MCP session.
    loader.api_server = server
    await server.serve()
