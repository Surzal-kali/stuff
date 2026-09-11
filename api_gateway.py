import asyncio
import contextvars
import json
import logging
import os
import secrets
import threading
import time
import uuid
from pathlib import Path

# --- .env loading (sudo-safe) ------------------------------------------------
# When the framework is launched under sudo, the shell environment is stripped
# and .env is never sourced.  Load it here so all env vars are available
# regardless of how the process is started.  python-dotenv only sets vars not
# already in os.environ, so shell exports always win.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:
    pass

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, Optional
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Per-request HTTP trace (gap-h root-cause hunt).  Append-only JSONL to
# /tmp/gw_http_trace.log; one line per event.  Never raises into the request
# path — instrumentation must not itself become a fault source.
# ---------------------------------------------------------------------------
_TRACE_PATH = "/tmp/gw_http_trace.log"
_trace_lock = threading.Lock()
_in_flight = 0                       # current accepted-but-not-completed requests
_op_id_var: contextvars.ContextVar = contextvars.ContextVar("gw_op_id", default=None)
_disp_result_len_var: contextvars.ContextVar = contextvars.ContextVar(
    "gw_disp_result_len", default=0
)


def _trace(event: str, **fields) -> None:
    """Append one structured JSON line to the trace log. Best-effort, never raises."""
    try:
        rec = {"event": event, "ts": time.time()}
        rec.update(fields)
        line = json.dumps(rec, default=str)
        with _trace_lock:
            with open(_TRACE_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        logging.getLogger(__name__).debug("trace write failed", exc_info=True)


def _get_nested(d, dotted: str):
    """Best-effort nested key lookup 'a.b.c' on a dict; returns None on any miss."""
    cur = d
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _mcp_text(payload) -> list:
    """Serialize a payload to a single MCP TextContent list and record its
    byte length for the DISPATCH_DONE trace. Centralizes the json.dumps so
    every success return path reports response-composition size."""
    text = json.dumps(payload, default=str)
    try:
        _disp_result_len_var.set(len(text.encode("utf-8", "replace")))
    except Exception:
        pass
    return [mcp_types.TextContent(type="text", text=text)]

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
        # Only HTTP requests carry the client-addr + reply-leg signals we want.
        # Lifespan/non-http scopes pass through uninstrumented.
        if scope.get("type") != "http":
            await self._sm.handle_request(scope, receive, send)
            return

        global _in_flight
        op_id = uuid.uuid4().hex[:12]
        client = scope.get("client") or [None, None]
        client_addr = f"{client[0]}:{client[1]}" if client and client[0] else "unknown"
        in_flight_before = _in_flight
        _in_flight += 1
        t0 = time.monotonic()
        _trace(
            "REQUEST_START",
            op_id=op_id,
            client_addr=client_addr,
            in_flight=in_flight_before,
            http_method=scope.get("method"),
            path=scope.get("path"),
        )
        token = _op_id_var.set(op_id)

        resp_bytes = 0
        resp_status = None
        write_ok = True
        exc_type = None

        async def send_wrap(message):
            nonlocal resp_bytes, resp_status, write_ok, exc_type
            try:
                if message.get("type") == "http.response.start":
                    resp_status = message.get("status")
                elif message.get("type") == "http.response.body":
                    resp_bytes += len(message.get("body") or b"")
                await send(message)
            except Exception as e:
                # Client that timed out and closed its socket surfaces HERE as
                # ConnectionResetError / BrokenPipeError / similar. This is the
                # reply-leg-loss signature we are hunting.
                write_ok = False
                exc_type = type(e).__name__
                _trace(
                    "WRITE_EXC",
                    op_id=op_id,
                    exc_type=exc_type,
                    exc_msg=str(e),
                    elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
                    resp_bytes_so_far=resp_bytes,
                )
                raise

        async def receive_wrap():
            msg = await receive()
            # Parse the JSON-RPC body once on the first http.request chunk to
            # extract the jsonrpc id, method, and (for tools/call) the tool name
            # + tool_id. Best-effort: never break the request on a parse miss.
            if msg.get("type") == "http.request":
                body = msg.get("body") or b""
                try:
                    rpc = json.loads(body) if body else None
                    cand = None
                    batch_n = None
                    if isinstance(rpc, dict):
                        cand = rpc
                    elif isinstance(rpc, list) and rpc and isinstance(rpc[0], dict):
                        cand = rpc[0]
                        batch_n = len(rpc)
                    if cand is not None:
                        _trace(
                            "REQUEST_PARSED",
                            op_id=op_id,
                            batch=batch_n,
                            jsonrpc_id=cand.get("id"),
                            rpc_method=cand.get("method"),
                            tool=_get_nested(cand, "params.name"),
                            tool_id=_get_nested(cand, "params.arguments.tool_id"),
                        )
                except Exception:
                    _trace("REQUEST_PARSE_FAIL", op_id=op_id, body_len=len(body))
            return msg

        try:
            await self._sm.handle_request(scope, receive_wrap, send_wrap)
        except Exception as e:
            _trace(
                "HANDLER_EXC",
                op_id=op_id,
                exc_type=type(e).__name__,
                exc_msg=str(e),
                elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
            )
            raise
        finally:
            _in_flight -= 1
            _op_id_var.reset(token)
            _trace(
                "RESPONSE_DONE",
                op_id=op_id,
                elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
                response_bytes=resp_bytes,
                status=resp_status,
                write_completed=write_ok,
                exc_type=exc_type,
                in_flight_after=_in_flight,
            )

from daharness import ToolRegistry, OllamaEmbeddingFunction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models shared by the REST endpoints and the MCP tool wrappers.
# ---------------------------------------------------------------------------
class ToolRequest(BaseModel):
    intent: Optional[str] = None
    # When tool_id is supplied, skip semantic search and execute that exact
    # tool (the model picked it from a tools_search menu).  When only intent
    # is supplied, fall back to the legacy auto-resolve-and-execute path.
    tool_id: Optional[str] = None
    arguments: Optional[dict] = None
    # agent_id doubles as the Brain session id and scopes memory reads/writes.
    # Must be a TOP-LEVEL request field, NOT a tool argument (concurrent MCP
    # clients each pass their own; tool schemas stay clean).
    agent_id: Optional[str] = None

class ToolSearchRequest(BaseModel):
    intent: str
    top_k: Optional[int] = 5
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
        "intent": {
            "type": "string",
            "description": (
                "Natural-language description of what the caller wants. "
                "Used to auto-resolve the best matching tool when tool_id "
                "is NOT supplied. Ignored when tool_id is supplied."
            ),
        },
        "tool_id": {
            "type": "string",
            "description": (
                "Exact tool id (dotted python path, e.g. "
                "'auxiliaries.nmap.run_scan') from a tools_search result. "
                "When supplied, this tool is executed directly — no semantic "
                "search is performed. Call tools_search first to get the menu "
                "of candidates, then pass the chosen tool_id here."
            ),
        },
        "arguments": {"type": "object"},
        "agent_id": {
            "type": "string",
            "description": "Identity of the running model/agent. Used as the Brain session id so concurrent agents get isolated tool state (e.g. separate msfconsole handles). Omit to use the shared default session.",
        },
    },
    # At least one of intent or tool_id must be present; validated in the handler.
}
_MCP_TOOL_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "intent": {
            "type": "string",
            "description": (
                "Natural-language description of what the caller wants. "
                "Returns up to top_k candidate tools with their ids, "
                "capabilities, parameter schemas, and semantic distances. "
                "Call this BEFORE tools_execute so the model can pick the "
                "right tool from the menu instead of relying on auto-resolve."
            ),
        },
        "top_k": {
            "type": "integer",
            "default": 5,
            "description": "Number of candidate tools to return (max 10).",
        },
        "agent_id": {
            "type": "string",
            "description": "Identity of the running model/agent (scopes tool state). Omit for the shared default session.",
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
TOOL_SEARCH = "tools_search"
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
            # Two dispatch modes:
            # 1. tool_id supplied → execute that exact tool (model picked it
            #    from a /tools/search menu).  Skip semantic search entirely.
            # 2. only intent supplied → legacy auto-resolve-and-execute:
            #    find_best_tool picks the single best match and fires it.
            if req.tool_id:
                manifest = await self.tool_registry.find_tool_by_id(req.tool_id)
                if not manifest:
                    raise HTTPException(404, f"No tool found with id '{req.tool_id}'")
            else:
                if not req.intent:
                    raise HTTPException(400, "Either 'intent' or 'tool_id' is required")
                manifest = await self.tool_registry.find_best_tool(req.intent)
                if not manifest:
                    raise HTTPException(404, "No tool found for intent")

            # Reject kwargs not declared in the tool manifest schema before
            # dispatch.  The secretary path already does this via
            # _normalize_args_against_manifest (which raises ModelRetry on
            # unknown keys); the API path had no such gate, so a caller (or
            # model) passing the wrong sibling's args silently got a
            # TypeError deep inside the tool instead of a loud 422.  This
            # is what stopped sqlmap from firing: the model passed args
            # belonging to a different tool and the dispatch went through
            # anyway because nothing checked the schema.
            unknown = self._check_unknown_args(manifest, req.arguments or {})
            if unknown:
                raise HTTPException(
                    422,
                    f"Arguments not in tool '{manifest.module_id}' schema: {unknown}. "
                    f"Accepted keys: {sorted(self._manifest_param_names(manifest))}",
                )

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

        @self.app.post("/tools/search")
        async def search_tools(req: ToolSearchRequest):
            """Return a menu of up to top_k candidate tools for an intent.

            Mirrors the secretary's search_tools: the model calls this first,
            picks a tool_id from the results, then calls /tools/execute with
            that tool_id.  This avoids the misfires that happen when
            /tools/execute auto-resolves a vague intent to the wrong sibling.
            """
            from daharness.registry import SECRETARY_MAX_TOP_K
            top_k = max(1, min(int(req.top_k or 5), SECRETARY_MAX_TOP_K))
            manifests = await self.tool_registry.find_tools(req.intent, top_k=top_k)
            if not manifests:
                raise HTTPException(404, "No tools found for intent")
            return {
                "intent": req.intent,
                "candidates": [
                    self.tool_registry.describe_manifest(m, lean=True) for m in manifests
                ],
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
                    name=TOOL_SEARCH,
                    description=(
                        "Semantic search over the tool registry. Returns a menu "
                        "of up to top_k candidate tools (id, capability, parameter "
                        "schema, semantic distance) for a natural-language intent. "
                        "ALWAYS call this BEFORE tools_execute so the model can "
                        "pick the right tool from the menu instead of relying on "
                        "auto-resolve, which misfires on ambiguous intents. "
                        "Mirrors POST /tools/search."
                    ),
                    inputSchema=_MCP_TOOL_SEARCH_SCHEMA,
                ),
                mcp_types.Tool(
                    name=TOOL_EXECUTE,
                    description=(
                        "Execute a tool. Two modes: (1) Pass tool_id (from a "
                        "tools_search result) to execute that exact tool directly "
                        "— preferred, no semantic search. (2) Pass only intent to "
                        "auto-resolve and execute the best single match — legacy "
                        "mode, prone to misfiring on ambiguous intents. Mirrors "
                        "POST /tools/execute."
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
            dispatch_id = uuid.uuid4().hex[:12]
            linked_op = _op_id_var.get()
            disp_t0 = time.monotonic()
            _trace(
                "DISPATCH_START",
                dispatch_id=dispatch_id,
                op_id=linked_op,
                tool=name,
                tool_id=arguments.get("tool_id"),
            )
            _disp_result_len_var.set(0)
            try:
                if name == TOOL_SEARCH:
                    intent = arguments.get("intent")
                    if not intent:
                        return self._error(f"{TOOL_SEARCH}: 'intent' is required")
                    from daharness.registry import SECRETARY_MAX_TOP_K
                    top_k = max(1, min(int(arguments.get("top_k") or 5), SECRETARY_MAX_TOP_K))
                    manifests = await self.tool_registry.find_tools(intent, top_k=top_k)
                    if not manifests:
                        return self._error(f"No tools found for intent: {intent}")
                    candidates = [
                        self.tool_registry.describe_manifest(m, lean=True) for m in manifests
                    ]
                    payload = {"intent": intent, "candidates": candidates}
                    return _mcp_text(payload)

                if name == TOOL_EXECUTE:
                    tool_id = arguments.get("tool_id")
                    intent = arguments.get("intent")

                    # Mode 1: explicit tool_id → execute directly, no search.
                    if tool_id:
                        manifest = await self.tool_registry.find_tool_by_id(tool_id)
                        if not manifest:
                            return self._error(f"No tool found with id '{tool_id}'")
                    # Mode 2: intent only → legacy auto-resolve-and-execute.
                    elif intent:
                        manifest = await self.tool_registry.find_best_tool(intent)
                        if not manifest:
                            return self._error(f"No tool found for intent: {intent}")
                    else:
                        return self._error(
                            f"{TOOL_EXECUTE}: either 'tool_id' or 'intent' is required. "
                            "Call tools_search first to get candidate tool_ids."
                        )
                    tool_args = arguments.get("arguments") or {}
                    # Mirror the REST 422 gate: reject kwargs not in the tool
                    # manifest schema so wrong-sibling arg mismatches are
                    # LOUD, not silent TypeErrors deep in the tool body.
                    unknown = self._check_unknown_args(manifest, tool_args)
                    if unknown:
                        return self._error(
                            f"{TOOL_EXECUTE}: Arguments not in tool "
                            f"'{manifest.module_id}' schema: {unknown}. "
                            f"Accepted keys: {sorted(self._manifest_param_names(manifest))}"
                        )
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
                    return _mcp_text(payload)

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
                    return _mcp_text(result)

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
                    return _mcp_text(result)

                return self._error(f"Unknown MCP tool: {name}")
            except Exception as exc:  # noqa: BLE001 - surface to the MCP client
                logger.error("[gateway] MCP call_tool '%s' failed: %s", name, exc, exc_info=True)
                return self._error(f"{name}: {exc}")
            finally:
                _trace(
                    "DISPATCH_DONE",
                    dispatch_id=dispatch_id,
                    op_id=linked_op,
                    tool=name,
                    dispatch_ms=round((time.monotonic() - disp_t0) * 1000, 2),
                    result_bytes=_disp_result_len_var.get(),
                )

    # --- Arg validation helpers (mirror _normalize_args_against_manifest) -----

    @staticmethod
    def _manifest_param_names(manifest) -> list:
        """Return the declared parameter names from the manifest schema."""
        params = manifest.parameters or {}
        if isinstance(params, dict):
            props = params.get("properties")
            if isinstance(props, dict):
                return list(props.keys())
        return []

    def _check_unknown_args(self, manifest, arguments: dict) -> list:
        """Return a list of argument keys not declared in the manifest schema.

        Mirrors the extra-key rejection in
        ``_normalize_args_against_manifest`` (agent.py) so the API path
        gets the same loud failure the secretary path already has.
        Tolerates case differences and meta-keys prefixed with ``_``
        (e.g. ``_raw``) for parity with the secretary path.
        """
        if not isinstance(arguments, dict) or not arguments:
            return []
        declared = set(APIGateway._manifest_param_names(manifest))
        declared_lower = {d.lower() for d in declared}
        unknown = []
        for key in arguments:
            if key in declared or key.lower() in declared_lower:
                continue
            if key.startswith("_"):
                continue
            unknown.append(key)
        return unknown

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
