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


# --- Per-turn live-session snapshot (Layer 4) ---


def _session_state_block() -> str:
    """Build a compact snapshot of live sessions to append to the user prompt
    at the start of each turn — but ONLY when at least one session is visible.

    Why the "only when non-empty" rule: appending a "(none visible here) …
    call list_sessions first" block to *every* turn (including creation turns
    like ssh_connect / open_listener) is pure noise that can nudge a small,
    throughput-stressed model away from calling the right create tool. When
    there is nothing to ground on, inject nothing; when there are live
    sessions, list their typed handles so the model has fresh, copy-pasteable
    references.

    Best-effort w.r.t. the documented "process-local sessions" pitfall:
    sessions created on the Brain sidecar live in that process's SessionManager
    and are NOT visible to this (harness) process.  In that case nothing is
    injected here, and the model should call ``list_sessions`` (which
    dispatches through the Brain and sees them).
    """
    try:
        from utils.session_manager import get_manager
        handles = [
            f"  - {s['kind']}:{s['sid']} -> {s['target']}"
            for s in get_manager().list_sessions()
        ]
    except Exception:
        return ""
    if not handles:
        return ""
    return (
        "\n[Active sessions visible to this process right now — when acting on "
        "a session, copy the exact handle shown here]\n" + "\n".join(handles)
    )


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


# --- Chaining nudge for tools that hand off to another tool ---

# Maps a tool's module_id to the next-step instruction the model should follow
# using the value(s) that tool returned.  Kept explicit (not auto-derived from
# schemas) because the whole point is to remove the model's ambiguity about
# "is this string a tool id or an argument value?".
_CHAIN_NEXT = {
    "payloads.metasploiting.MetasploitClient.index_modules": (
        "Next: call execute_tool with tool_id "
        "'payloads.metasploiting.MetasploitClient.execute_module', passing one of the "
        "returned 'module_path' values VERBATIM as the 'module_path' argument (it is a "
        "VALUE, not a tool id) and RHOSTS/PAYLOAD/etc. in 'options'."
    ),
    "payloads.metasploiting.MetasploitClient.execute_module": (
        "If a new session was reported: next call execute_tool with tool_id "
        "'payloads.metasploiting.MetasploitClient.interact_session', passing the 'msf:' "
        "handle VERBATIM as the 'handle' argument (a VALUE, not a tool id)."
    ),
    "utils.paramiko_client.ssh_connect": (
        "Next: call execute_tool with tool_id 'utils.paramiko_client.ssh_exec' "
        "(or 'ssh_shell' for a PTY), passing the returned 'ssh:' handle VERBATIM as "
        "the 'handle' argument (a VALUE, not a tool id)."
    ),
    "listeners.listening.TCPListener.open_listener": (
        "Next: use the returned 'listener:' handle with the payload/connector that "
        "calls back to it (a VALUE, not a tool id). Stop it later with "
        "'listeners.listening.TCPListener.close_listener'."
    ),
}


def _chaining_hint(tool_id: str, result: Dict[str, Any]) -> str:
    """Return a one-line next-step hint for chaining tools, or ''.

    Only emitted on a non-failed result so a hint never nudges the model to
    build on a tool that just errored.
    """
    hint = _CHAIN_NEXT.get(tool_id)
    if not hint:
        return ""
    status = str(result.get("status", "")).lower()
    if status == "failed":
        return ""
    return hint


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
    # Layer 0 (disambiguation): MSF module_path values look like
    # "auxiliary/scanner/ssh/ssh_login" and real tool ids are slash-free
    # dotted python paths.  Reject a slash-bearing tool_id *here* — before the
    # surfaced-set lookup — so the model's confusion ("I'll just pass the
    # module_path as a tool id") is turned into a self-correcting ModelRetry
    # that names the right wrapper tool, instead of a generic "not found".
    if "/" in tool_id:
        raise ModelRetry(
            f"'{tool_id}' contains '/', so it looks like an MSF module_path (a value "
            f"you pass to a tool), not a tool id. Tool ids are dotted python paths "
            f"such as 'payloads.metasploiting.MetasploitClient.execute_module'. "
            f"To run the module '{tool_id}', call execute_tool with tool_id "
            f"'payloads.metasploiting.MetasploitClient.execute_module' and pass '{tool_id}' "
            f"as the 'module_path' argument."
        )
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

    # Layer 1: tolerate the legacy ``session_id`` argument name on tools that
    # now take a typed ``handle`` (small models often still emit the old name).
    args = registry.normalize_handle_argument(manifest, args)

    # Layer 1: refuse to let a handle from the wrong namespace flow into a
    # tool.  This is the disambiguation gate — it converts the silent
    # cross-namespace failure (e.g. an msf: handle into ssh_exec) into a
    # self-correcting ModelRetry that names the correct tool to use.
    handle_reason = registry.validate_handle_argument(manifest, args)
    if handle_reason is not None:
        raise ModelRetry(handle_reason)

    warnings = registry.validate_arguments(manifest, args)
    result = await registry.execute_tool(manifest, args)
    if isinstance(result, dict) and warnings:
        result = {**result, "argument_warnings": warnings}

    # Cap stdout so large tool outputs don't blow up the model's context window.
    if isinstance(result, dict):
        result = _cap_tool_stdout(result)

    # Chaining nudge: tools that "interface with other tools" return values
    # (module_path / typed handle) the model must carry into the NEXT tool call
    # as an *argument*, not as a tool_id.  Small secretary models routinely
    # drop the chain here (logs.txt turns 6-10: "executed no tool this turn").
    # Appending a one-line "next step" hint to the result keeps the chain alive
    # without re-running search_tools or guessing a tool id.
    if isinstance(result, dict):
        hint = _chaining_hint(manifest.module_id, result)
        if hint:
            result = {**result, "next_step_hint": hint}

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

            Tool IDs vs argument values (CRITICAL — this is the main failure mode):
            - A tool ID is a dotted python path with NO slashes, e.g.
              'payloads.metasploiting.MetasploitClient.execute_module'. You pass it as
              the `tool_id` argument to execute_tool.
            - An MSF module_path like 'auxiliary/scanner/ssh/ssh_login' is an ARGUMENT
              VALUE you pass to execute_module's `module_path` parameter. It is NEVER a
              tool id and execute_tool will reject it if you pass it as one.
            - A session handle like 'msf:1' or 'ssh:sess-0001' is an ARGUMENT VALUE you
              pass to a tool's `handle` parameter. It is NEVER a tool id.
            - Chaining: when a tool returns a value you need for the next step
              (index_modules -> module_path -> execute_module; execute_module -> msf:
              handle -> interact_session; ssh_connect -> ssh: handle -> ssh_exec), your
              NEXT action is execute_tool with the matching wrapper tool, passing that
              returned value as its argument. Do NOT search again, do NOT pass the value
              as a tool_id, do NOT skip the next call.

            Session handles (IMPORTANT — this is where mistakes happen):
            - Sessions are identified by TYPED handles of the form "<kind>:<id>":
              "ssh:sess-0001" (paramiko SSH), "msf:1" (Metasploit), "listener:tcp-4444"
              (a bound listener). The prefix names the namespace and is enforced: a tool
              that accepts only ssh: handles will reject an msf: handle with a message
              telling you which tool to use instead. Heed that message.
            - ALWAYS copy a handle returned by a tool VERBATIM into the next tool's `handle`
              argument. Never retype it, shorten it, or substitute one namespace's handle
              for another tool's (e.g. do not pass an msf: handle to ssh_exec).
            - Before interacting with a session when you are unsure which one to use, call
              `list_sessions` (the one that lists ALL namespaces) and pick the matching
              handle by its target/kind. Do not guess a handle from memory.
            - Tools that take a handle declare `accepted_handle_kinds` in their manifest.
            - Close sessions you no longer need: ssh_close for ssh:, close_msf_session for
              msf:, close_listener for listener:.

            Listeners vs backdoors (do not confuse these):
            - A LISTENER is something YOU bind locally to RECEIVE a callback (e.g. for a
              reverse shell payload). Use open_listener; it returns a listener: handle and
              you stop it with close_listener. You do NOT connect to a listener.
            - A BACKDOOR is already running on the target (e.g. vsftpd 2.3.4 on port 6200).
              You do NOT bind anything for it — you pop it with a Metasploit exploit module
              (execute_module), which returns an msf: handle you use with interact_session.

            SSH login on a target:
            - For a plain username/password SSH login, use ssh_connect (it handles old/legacy
              SSH servers automatically and returns an ssh: handle). Do NOT reach for
              Metasploit's ssh_login auxiliary just because the target is old — that creates
              an msf: session in a DIFFERENT namespace and is the main source of "which
              session do I use?" confusion. Reserve ssh_login for cases where you specifically
              need a Metasploit session (e.g. to pivot through MSF), and when you do use it,
              treat its result as an msf: handle, never as an ssh: handle.
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

        # Layer 4: re-ground the model on the live-session state at the start
        # of every turn.  This is best-effort — sessions created on the Brain
        # sidecar live in that process's SessionManager and may not be visible
        # here (see AGENTS.md "Process-local sessions").  When nothing is
        # visible we explicitly tell the model to call list_sessions, which
        # dispatches through the Brain and sees those sessions correctly.
        prompt_with_state = user_prompt + _session_state_block()

        async def _run():
            result = await self.secretary.run(
                prompt_with_state, deps=deps, message_history=message_history
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
    print("[chat] Secretary ready. Type 'exit' to quit. Type '/clear' to reset conversation history.")
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

        if user_input.strip().lower() == "/clear":
            history = None
            deps = SecretaryDeps(registry=registry)
            print("[chat] Conversation history cleared.")
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
