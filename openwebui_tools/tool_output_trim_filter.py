"""
title: Tool Output Trim (head+tail)
author: on-box agent (local, self-hosted - no community import)
version: 1.0.0
description: Always-on inlet Filter that head+tail truncates long tool results before they reach the LLM. Pure stdlib, no network calls, no eval, no filesystem access.
required_open_webui_version: 0.5.0
"""

import logging

from pydantic import BaseModel, Field

log = logging.getLogger("open_webui.filters.tool_output_trim")

_MARKER = "\n... [truncated {elided} chars by tool_output_trim] ...\n"


class Filter:
    """
    Intercept every chat-completion request BEFORE the model sees it.

    Why head+tail: final lines of tool/web output carry verdicts and
    summaries (same rationale as daharness/agent.py T-001), so we keep a
    tail slice, not just the head.

    Why idempotent: each tool message is truncated by a rule that depends
    ONLY on its own content (cap, tail, marker). The same message produces
    the same text on every subsequent turn, so conversation history stays
    byte-stable and llama.cpp keeps its KV prefix cache between turns.
    With --parallel 1 and --no-context-shift that prefix reuse is what
    keeps per-turn prefill incremental instead of a full 55K-token re-read.

    Scope: only role=='tool' messages are touched by default. Your own
    long pasted inputs are never modified unless you flip SCAN_USER_MESSAGES.
    """

    class Valves(BaseModel):
        MAX_CHARS_PER_TOOL_RESULT: int = Field(
            default=4000,
            description=(
                "Per-message character cap for tool results (~4 chars/token, so "
                "4000 chars is roughly a 1K-token budget per tool call). Framework "
                "bridge already caps at 8000 - this is the second, tighter layer."
            ),
        )
        MAX_TAIL_CHARS: int = Field(
            default=1000,
            description="Max tail characters kept after the truncation marker.",
        )
        SCAN_USER_MESSAGES: bool = Field(
            default=False,
            description=(
                "Also head+tail truncate very long user messages (covers WebUI "
                "native web-search <source> injections). Leave OFF if you paste "
                "your own long content into chat - it would be truncated too."
            ),
        )
        MAX_CHARS_PER_USER_MESSAGE: int = Field(
            default=8000,
            description="Per-message cap for user messages when SCAN_USER_MESSAGES is on.",
        )
        MAX_TAIL_CHARS_USER: int = Field(
            default=1000,
            description="Tail cap for user-message truncation.",
        )

    def __init__(self):
        self.valves = self.Valves()

    # --- core ---------------------------------------------------------------

    def _head_tail(self, text: str, cap: int, tail_cap: int) -> str:
        if cap <= 0 or len(text) <= cap:
            return text
        tail_len = min(tail_cap, cap // 4)
        head_len = cap - tail_len
        elided = len(text) - head_len - tail_len
        marker = _MARKER.format(elided=elided)
        return text[:head_len] + marker + text[-tail_len:]

    def _trim_messages(self, messages, role: str, cap: int, tail_cap: int) -> int:
        changed = 0
        for msg in messages:
            if not isinstance(msg, dict) or msg.get("role") != role:
                continue
            content = msg.get("content")
            # Skip multimodal / non-string contents - only trim plain text.
            if not isinstance(content, str):
                continue
            if len(content) <= cap:
                continue
            msg["content"] = self._head_tail(content, cap, tail_cap)
            changed += 1
        return changed

    # --- Open WebUI hook ------------------------------------------------------

    def inlet(self, body: dict, __event_emitter__=None, __user__: dict = None):
        try:
            messages = body.get("messages")
            if not isinstance(messages, list):
                return body

            v = self.valves
            trimmed_tools = self._trim_messages(
                messages, "tool", v.MAX_CHARS_PER_TOOL_RESULT, v.MAX_TAIL_CHARS
            )
            trimmed_user = 0
            if v.SCAN_USER_MESSAGES:
                trimmed_user = self._trim_messages(
                    messages,
                    "user",
                    v.MAX_CHARS_PER_USER_MESSAGE,
                    v.MAX_TAIL_CHARS_USER,
                )

            if (trimmed_tools or trimmed_user) and __event_emitter__ is not None:
                try:
                    note = f"tool_output_trim: {trimmed_tools} tool result(s)"
                    if trimmed_user:
                        note += f", {trimmed_user} user message(s)"
                    note += " head+tail truncated."
                    __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": note, "done": True, "hidden": False},
                        }
                    )
                except Exception:
                    pass  # emitter is inert for direct API callers; never fatal

        except Exception as e:
            # Fail open: an error in this filter must never break the request.
            log.exception("tool_output_trim inlet failed, passing body through: %s", e)

        return body