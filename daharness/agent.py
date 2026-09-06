"""Secretary agent API: the conversational tool-selection loop.

This module owns:
* :class:`SecretaryDeps` — per-conversation state.
* the ``search_tools``/``execute_tool`` tool functions the secretary model calls.
* :class:`SecretaryMixin` — the ``run_secretary`` / agent-construction methods
  mixed into :class:`daharness.registry.ToolRegistry`.
* :func:`create_secretary_agent` and the interactive ``_chat`` REPL.
"""

import asyncio
import inspect
import json
import logging
import os
import textwrap
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from pydantic_ai import (
    Agent,
    DeferredToolRequests,
    FunctionToolset,
    ModelRetry,
    RunContext,
    Tool,
    ToolApproved,
    ToolDenied,
    capture_run_messages,
)
from pydantic_ai.messages import ModelMessage

from .models import ToolManifest

logger = logging.getLogger(__name__)


# --- Secretary per-conversation state ---


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
    search_calls: int = 0
    execute_calls: int = 0
    # Hard limit on search_tools calls within a single run_secretary turn.
    # Without this, a confused small model can loop on search_tools (which
    # needs no approval) dozens of times within one run(), pegging the GPU
    # at 100% for minutes without ever calling execute_tool.
    max_search_calls: int = field(default_factory=lambda: int(os.getenv("SECRETARY_MAX_SEARCH_CALLS", "5")))

    def record_surfaced(self, manifests: List[ToolManifest]) -> None:
        for manifest in manifests:
            self.surfaced_tools[manifest.module_id] = manifest

    def get_surfaced(self, tool_id: str) -> Optional[ToolManifest]:
        return self.surfaced_tools.get(tool_id)


# --- Human-in-the-loop confirmation + argument normalisation ---


async def _cli_confirmer(summary: Dict[str, Any]) -> bool:
    """Default human-in-the-loop gate: print full metadata, ask y/N on stdin."""
    print("\n===== EXECUTION CONFIRMATION =====")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("==================================")
    answer = await asyncio.to_thread(input, "Approve execution? [y/N]: ")
    return answer.strip().lower() in {"y", "yes"}


async def _run_confirmer(
    confirmer: Callable[[Dict[str, Any]], Any], summary: Dict[str, Any]
) -> bool:
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


def _cap_tool_stdout(result: Dict[str, Any], limit: Optional[int] = None) -> Dict[str, Any]:
    """Truncate the ``stdout`` field of a tool result before it enters the
    model's conversation history.

    Large outputs (nmap XML, MSF console dumps) can blow up the context window
    and crowd out the reasoning the model needs.  The full output is always
    available in the server-side logs; the model gets a truncated view with a
    marker showing how many characters were elided.

    ``limit`` defaults to ``TOOL_STDOUT_CAP`` (8000 chars).  Set to 0 to disable.
    """
    if limit is None:
        limit = int(os.getenv("TOOL_STDOUT_CAP", "8000"))
    if limit <= 0:
        return result
    stdout = result.get("stdout")
    if isinstance(stdout, str) and len(stdout) > limit:
        elided = len(stdout) - limit
        result = {**result, "stdout": stdout[:limit] + f"\n... [truncated {elided} chars]"}
    return result


# --- Secretary tool functions (called by the agent loop) ---


async def secretary_search_tools(
    ctx: RunContext[SecretaryDeps], query: str, top_k: int = 5
) -> List[Dict[str, Any]]:
    """Semantic search over the tool registry.

    Returns FULL manifests (id, capability, implementation path, transport,
    parameters, semantics). The tool_ids returned here are the only ids that
    `execute_tool` will accept.
    """
    # Constants live on the registry module; import lazily to avoid a circular
    # import (registry mixes SecretaryMixin in at class-definition time).
    from .registry import SECRETARY_MAX_TOP_K

    registry = ctx.deps.registry
    limit = max(1, min(int(top_k or 5), SECRETARY_MAX_TOP_K))
    ctx.deps.search_calls += 1
    if ctx.deps.search_calls > ctx.deps.max_search_calls:
        raise ModelRetry(
            f"You have called search_tools {ctx.deps.search_calls} times in this turn without converging. "
            "Either pick a tool from the results you already have and call execute_tool, "
            "or tell the user you cannot fulfill the request. Do NOT search again."
        )
    logger.info(f"[secretary] search_tools query={query!r} top_k={limit} (call #{ctx.deps.search_calls}/{ctx.deps.max_search_calls})")
    manifests = await registry.find_tools(query, top_k=limit)
    ctx.deps.record_surfaced(manifests)
    return [registry.describe_manifest(m, lean=True) for m in manifests]


async def secretary_execute_tool(
    ctx: RunContext[SecretaryDeps],
    tool_id: str,
    arguments: Any = None,
) -> Dict[str, Any]:
    """Execute a tool that was surfaced by `search_tools` in this conversation.

    This call requires human approval; a confirmation showing the full module
    metadata and the arguments is presented before anything runs.

    `arguments` tolerates a JSON-encoded string because small secretary models
    routinely emit the nested object as a string; a malformed payload is
    normalized (or wrapped as `{"_raw": ...}`) here instead of burning the
    tool's retry budget on a schema validation error.
    """
    registry = ctx.deps.registry
    tool_id = (tool_id or "").strip()
    args = _parse_tool_args(arguments)
    ctx.deps.execute_calls += 1
    logger.info(
        f"[secretary] execute_tool requested: {tool_id} args={json.dumps(args, default=str)[:300]}"
    )

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

    if isinstance(args, dict) and "_raw" in args:
        logger.warning(
            f"[secretary] execute_tool '{tool_id}': arguments were not a valid "
            f"JSON object; passing raw payload {str(args.get('_raw'))[:200]!r}"
        )
    warnings = registry.validate_arguments(manifest, args)
    result = await registry.execute_tool(manifest, args)
    if isinstance(result, dict) and warnings:
        result = {**result, "argument_warnings": warnings}

    # Cap stdout so large tool outputs don't blow up the model's context window.
    if isinstance(result, dict):
        result = _cap_tool_stdout(result)

    # Post-execution log dump: this function body only runs once pydantic-ai
    # has granted approval (execute_tool is declared requires_approval=True),
    # so by the time we get here the operator said "go" and the tool already
    # produced its side effects. Tailing the framework logs gives visibility
    # into what the Brain sidecar and MSF console actually did — but only when
    # it's useful. Controlled by POST_EXECUTION_LOGS env var:
    #   "off"       – never
    #   "failures"  – only when status == "Failed"  (default)
    #   "always"    – every execution
    post_logs_mode = os.getenv("POST_EXECUTION_LOGS", "failures").lower().strip()
    if post_logs_mode == "always" or (
        post_logs_mode == "failures"
        and isinstance(result, dict)
        and str(result.get("status", "")).lower() == "failed"
    ):
        if isinstance(result, dict):
            log_tail = await _tail_framework_logs()
            if log_tail:
                result = {**result, "post_execution_logs": log_tail}

    return result


async def _tail_framework_logs() -> Dict[str, str]:
    """Read the tail of the Brain and MSF log files after an approved tool run.

    Imported lazily so utils/log_reader.py isn't pulled in at module load
    (it imports constants, which would create a circular import otherwise).
    Errors are swallowed: a missing/unreadable log is not a reason to fail
    the whole tool call, just a visibility gap.
    """
    try:
        from utils.log_reader import read_logs
    except Exception as import_err:
        logger.warning(f"[secretary] could not import read_logs: {import_err}")
        return {}

    tails: Dict[str, str] = {}
    for log_type in ("brain", "msf"):
        try:
            tail = await asyncio.to_thread(read_logs, log_type, 15)
        except Exception as tail_err:
            logger.warning(f"[secretary] post-exec log tail ({log_type}) failed: {tail_err}")
            continue
        if isinstance(tail, str) and not tail.startswith("Error"):
            tails[log_type] = tail
        elif isinstance(tail, str):
            logger.info(f"[secretary] post-exec log ({log_type}): {tail}")
    return tails


# --- SecretaryMixin: agent construction + the approval-gated run loop ---


class SecretaryMixin:
    """Agent-loop behaviour for :class:`ToolRegistry`.

    Mixed in so the registry class stays focused on discovery while the
    conversational secretary (search -> approve -> execute -> report) lives
    here.
    """

    def _init_secretary_agent(self, model: Optional[Any] = None):
        """Build the conversational tool secretary.

        One agent, one loop: search -> select -> execute -> report. The model
        reaches tools only through `search_tools` (semantic retrieval), never
        by having the registry stuffed into its context. The final answer is
        plain text; swap `model` for a test double in unit tests.
        """
        from .registry import OLLAMA_BASE_URL  # lazy: avoid circular import

        if model is None:
            from pydantic_ai.models.ollama import OllamaModel
            from pydantic_ai.providers.ollama import OllamaProvider

            model = OllamaModel(
                self.secretary_model, provider=OllamaProvider(base_url=OLLAMA_BASE_URL)
            )

        toolset = FunctionToolset(
            [
                Tool(secretary_search_tools, takes_ctx=True, name="search_tools"),
                Tool(
                    secretary_execute_tool,
                    takes_ctx=True,
                    name="execute_tool",
                    requires_approval=True,
                ),
            ]
        )

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
            - You may call `search_tools` at most 5 times per turn. If you cannot find the right tool
              after searching, tell the user — do not keep searching.
            - When interacting with a shell session, a result like "[SUCCESS exit=0]" means the
              command worked even if there was no stdout. Do NOT retry a successful command.
            - Report results concisely. Do not repeat the full tool output verbatim.
            - When a tool returns structured JSON with labeled fields (e.g. "module_path"),
              copy the field value VERBATIM into your next tool call. Never abbreviate,
              shorten, or paraphrase values like module paths, session IDs, or tool IDs.
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

    def _pending_call_summary(self, call: Any, deps: SecretaryDeps) -> Dict[str, Any]:
        """Full-metadata summary of a pending execution for the human confirmer."""
        args = self._safe_parse_params(call.args)
        args = self._safe_parse_tool_args(args)
        tool_id = str(args.get("tool_id", "")) if isinstance(args, dict) else ""
        manifest = deps.get_surfaced(tool_id)
        if manifest is not None:
            base = self.describe_manifest(manifest)
        else:
            base = {
                "manifest": "NOT FOUND in this conversation's search results - deny unless you can verify it"
            }
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
        from .registry import (  # lazy: avoid circular import
            SECRETARY_MAX_APPROVAL_ROUNDS,
            SECRETARY_TURN_TIMEOUT,
        )

        confirmer = confirmer or self.confirmer
        deps = deps or SecretaryDeps(registry=self)

        # Reset per-turn counters so a new user prompt starts fresh.
        deps.search_calls = 0
        deps.execute_calls = 0

        async def _run():
            result = await self.secretary.run(
                user_prompt, deps=deps, message_history=message_history
            )

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
                    logger.info(
                        f"[TOOL_CONFIRM] Requesting approval: {json.dumps(summary, default=str)}"
                    )
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

        try:
            return await asyncio.wait_for(_run(), timeout=SECRETARY_TURN_TIMEOUT)
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Secretary turn exceeded {SECRETARY_TURN_TIMEOUT:.0f}s wall-clock timeout. "
                f"(search_calls={deps.search_calls}, execute_calls={deps.execute_calls}). "
                "The model may be stuck in a loop; reduce context or try a simpler prompt."
            )


# --- Public agent factory ---


def create_secretary_agent(registry, model=None):
    """Create the secretary configured for a registry."""
    return registry._init_secretary_agent(model=model)


# --- Interactive REPL ---


def _dump_turn_tool_activity(messages: List[Any], limit: int = 300) -> None:
    """Print the current turn's model activity: tool calls and retry feedback.

    Splits the captured history at the last UserPromptPart so only the failed
    turn's parts are printed, not the whole conversation.
    """
    start = 0
    for index, message in enumerate(messages):
        parts = getattr(message, "parts", None) or []
        if any(type(part).__name__ == "UserPromptPart" for part in parts):
            start = index
    print("[chat] --- model activity this turn ---")
    for message in messages[start:]:
        for part in getattr(message, "parts", None) or []:
            kind = type(part).__name__
            if kind == "ToolCallPart":
                print(f"[chat]   called {part.tool_name} args={str(part.args)[:limit]!r}")
            elif kind == "RetryPromptPart":
                print(f"[chat]   retry feedback: {str(part.content)[:limit]!r}")
    print("[chat] -------------------------------------")


async def _chat(registry: "ToolRegistry") -> None:
    """Interactive conversation with the secretary; one session, full history."""
    deps = SecretaryDeps(registry=registry)
    history = None
    print("[chat] Secretary ready. Type 'exit' to quit. Type '/stream <brain|msf>' to watch logs (Ctrl+C to stop).")
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

        if user_input.strip().startswith("/stream"):
            parts = user_input.strip().split()
            if len(parts) < 2:
                print("[chat] Usage: /stream <brain|msf>")
                continue
            log_type = parts[1]
            from utils.log_reader import stream_logs
            import threading
            stop_event = threading.Event()
            print(f"[chat] Streaming {log_type} logs... (Press Ctrl+C to stop)")

            def run_stream():
                for line in stream_logs(log_type, stop_event):
                    print(f"[{log_type}] {line}", end="")

            # Start streaming in a thread
            stream_thread = threading.Thread(target=run_stream, daemon=True)
            stream_thread.start()

            try:
                while stream_thread.is_alive():
                    # We use a short sleep in a thread to keep the main loop
                    # responsive to SIGINT (Ctrl+C)
                    await asyncio.sleep(0.1)
            except KeyboardInterrupt:
                stop_event.set()
                print(f"\n[chat] Stopped streaming {log_type} logs.")
            continue

        with capture_run_messages() as messages:
            try:
                result = await registry.run_secretary(
                    user_input.strip(), deps=deps, message_history=history
                )
            except Exception as exc:
                print(f"[chat] Error: {exc}")
                cause = exc.__cause__
                if cause is not None:
                    print(f"[chat]   caused by {type(cause).__name__}: {cause}")
                _dump_turn_tool_activity(messages)
                continue
        history = result.all_messages()
        print(f"secretary> {result.output}")


__all__ = [
    "SecretaryDeps",
    "SecretaryMixin",
    "create_secretary_agent",
    "secretary_execute_tool",
    "secretary_search_tools",
    "_chat",
    "_cli_confirmer",
    "_parse_tool_args",
    "_run_confirmer",
]
