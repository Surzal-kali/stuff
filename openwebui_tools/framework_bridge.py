"""
title: Framework Bridge (daharness gateway)
author: framework
description: Search + execute the framework's gated tool registry via the API gateway, with per-chat session isolation and framework memory access. Bug-bounty chat surface for Open Web UI.
version: 0.1.0
"""

import json
import os
import urllib.error
import urllib.request

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        gateway_url: str = Field(
            default="http://open-terminal:6000",
            description="Framework gateway base URL (from inside the open-webui container use http://open-terminal:6000; from the host use http://localhost:6000).",
        )
        api_key: str = Field(
            default="",
            description="GATEWAY_API_KEY (sent as X-API-Key). Falls back to the GATEWAY_API_KEY env var if the open-webui container has it exported.",
        )
        default_top_k: int = Field(
            default=5,
            ge=1,
            le=20,
            description="Default number of candidates returned by framework_search_tools.",
        )
        request_timeout: int = Field(
            default=600,
            ge=5,
            description="Seconds to wait on the gateway before giving up (long scans: prefer the framework's terminal_exec/terminal_status pattern).",
        )

    def __init__(self):
        self.valves = self.Valves()
        if not self.valves.api_key and os.getenv("GATEWAY_API_KEY"):
            self.valves.api_key = os.getenv("GATEWAY_API_KEY")

    # ------------------------------------------------------------------ helpers

    def _chat_agent_id(self) -> str:
        """Per-chat session isolation: Open WebUI injects __metadata__ with the
        chat_id. The gateway treats agent_id as the Brain session id, so each
        chat gets its own isolated tool state on the sidecar."""
        md = getattr(self, "__metadata__", None) or {}
        chat_id = md.get("chat_id") or md.get("id") or "0"
        return f"owui-{chat_id}"

    def _request(self, method: str, path: str, payload: dict, timeout: int | None = None) -> str:
        url = self.valves.gateway_url.rstrip("/") + path
        headers = {"Content-Type": "application/json"}
        if self.valves.api_key:
            headers["X-API-Key"] = self.valves.api_key
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8") if method == "POST" else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.valves.request_timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            return json.dumps(body, indent=2, default=str)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            return f"GATEWAY HTTP {e.code}: {detail}"
        except Exception as e:  # DNS failure, conn refused, timeout ...
            return (
                f"GATEWAY UNREACHABLE at {url}: {e!r}. "
                "Is the framework stack up? (dockered/up.sh; gateway on :6000)"
            )

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> str:
        return self._request("POST", path, payload, timeout)

    def _get(self, path: str, timeout: int | None = None) -> str:
        return self._request("GET", path, {}, timeout)

    # ------------------------------------------------------------------- tools

    def framework_search_tools(self, intent: str, top_k: int = 0) -> str:
        """Search the framework tool registry for tools matching a natural-language
        intent (e.g. "port scan a host", "check certificate details for a domain",
        "run zap against a url"). Returns a candidate menu: tool_id, capability,
        parameters JSON schema, semantic distance, and suggested next tools.

        ALWAYS call this first and pick a tool_id from the results; then call
        framework_run_tool with that exact tool_id. Do not guess tool ids.

        :param intent: Natural-language description of what you want to do.
        :param top_k: Max candidates to return (default from valve settings).
        """
        payload = {"intent": intent}
        payload["top_k"] = top_k if top_k and top_k > 0 else self.valves.default_top_k
        return self._post("/tools/search", payload)

    def framework_run_tool(self, tool_id: str, arguments: str = "{}", agent_id: str = "") -> str:
        """Execute a framework tool by exact tool_id (from framework_search_tools).

        :param tool_id: Exact tool_id from the search menu, e.g. 'auxiliaries.nmap.nmap_scan'.
        :param arguments: JSON object string of tool arguments, matching the
            parameters schema from the search menu. Unknown keys are rejected by
            the gateway with a 422 listing accepted keys. Example:
            '{"target": "10.0.0.5", "ports": "1-1000"}'
        :param agent_id: Optional explicit Brain session id. Leave empty to get
            an isolated per-chat session (recommended so parallel bug-bounty
            chats never share tool state). Reuse the same explicit value across
            chats to deliberately share state.
        """
        try:
            args = json.loads(arguments or "{}")
            if not isinstance(args, dict):
                return "ERROR: 'arguments' must be a JSON object string, e.g. '{\"target\": \"10.0.0.5\"}'"
        except json.JSONDecodeError as e:
            return f"ERROR: 'arguments' is not valid JSON ({e}). Pass a JSON object string."
        payload = {"tool_id": tool_id, "arguments": args}
        payload["agent_id"] = agent_id or self._chat_agent_id()
        return self._post("/tools/execute", payload)

    def framework_memory_search(self, query_text: str, namespace: str, agent_id: str = "") -> str:
        """Semantic search over the framework's memory service (findings, notes,
        prior program knowledge). Use it to recall what the framework already
        knows about a program/surface before re-running work.

        :param query_text: What to look for, e.g. 'grindr certificate pinning phase 0 results'.
        :param namespace: Memory namespace to search — REQUIRED, non-empty
            (e.g. 'findings', 'program_knowledge'). The REST API rejects an
            empty namespace with 500; "" is not a valid value.
        :param agent_id: Optional agent/session filter; defaults to this chat's session.
        """
        if not str(namespace).strip():
            return ("ERROR: 'namespace' is required and must be non-empty "
                    "(gateway rejects empty namespaces with 500). "
                    "Try e.g. 'findings' or 'program_knowledge'.")
        payload = {"query_text": query_text, "namespace": namespace}
        payload["agent_id"] = agent_id or self._chat_agent_id()
        return self._post("/memory/search", payload)

    def framework_health(self) -> str:
        """Check that the framework gateway is reachable and authenticated.
        No-op call: run this first if any framework_ tool errors."""
        return self._get("/health", timeout=10)