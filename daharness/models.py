"""Manifest models used by the harness."""

import os
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field

from constants import TransportType


class ToolManifest(BaseModel):
    module_id: str = Field(..., min_length=1)
    internal_semantic_capability: str = Field(..., min_length=1)
    external_sanitized_description: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    implementation_path: str = Field(..., min_length=1)
    internal_semantics: str = Field(..., min_length=1)
    transport: TransportType = TransportType.LOCAL_FILE
    endpoint: Optional[str] = None
    tool_name: Optional[str] = None
    # Typed session handle kinds this tool consumes (e.g. ("ssh",)).
    # Empty tuple means the tool takes no session handle.  Populated from the
    # @framework_tool(..., accepted_handle_kinds=...) decorator and persisted
    # in the ChromaDB metadata so it survives re-indexing.  The secretary
    # validates any ``handle`` argument's kind against this set before
    # execution and rejects cross-namespace calls with a ModelRetry.
    accepted_handle_kinds: Tuple[str, ...] = Field(default_factory=tuple)
    # Query-time annotation: cosine distance from the search query (lower =
    # more similar).  Not part of the tool definition — set by ``find_tools``
    # and surfaced in ``describe_manifest(lean=True)`` so the secretary model
    # can judge how well a result actually matches.
    distance: Optional[float] = None

    @classmethod
    def from_output(cls, payload: Any) -> Union["ToolManifest", List["ToolManifest"]]:
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, list):
            # Ensure we flatten the result to avoid List[List[ToolManifest]]
            results: List["ToolManifest"] = []
            for item in payload:
                res = cls.from_output(item)
                if isinstance(res, list):
                    results.extend(res)
                else:
                    results.append(res)
            return results
        if isinstance(payload, dict):
            # MSF-module-as-tool ingestion: mapping each Metasploit module dict
            # into a tool whose ``module_id`` *equals* the MSF module_path (e.g.
            # "auxiliary/scanner/ssh/ssh_login") creates a literal collision
            # between "a tool I call via execute_tool" and "a value I pass as
            # the module_path argument to dispatch_metasploit".  The secretary model
            # then passes the slash-path as a tool_id, dispatch routes it to the
            # metasploit endpoint, and MSF logs "Error loading plugin <path>".
            #
            # This branch is therefore OFF by default.  Only an explicit opt-in
            # (``DAHARNESS_INGEST_MSF=1``) re-enables it, and even then every
            # such "tool" carries a slash in its id so the slash-guard in
            # ``secretary_execute_tool`` will reject it as a tool_id — keeping
            # the two namespaces disjoint.
            if os.getenv("DAHARNESS_INGEST_MSF", "").lower() in {"1", "true", "yes"} and (
                "name" in payload or "description" in payload
            ):
                mapped_payload = {
                    "module_id": payload.get("name", "unknown_module"),
                    "internal_semantic_capability": payload.get(
                        "description", "No description provided"
                    ),
                    "external_sanitized_description": payload.get(
                        "description", "No description provided"
                    ),
                    "implementation_path": f"msf://{payload.get('name', 'unknown_module')}",
                    "internal_semantics": payload.get(
                        "description", "No description provided"
                    ),
                    "transport": TransportType.MCP_RPC,
                    "endpoint": "metasploit",
                }
                return cls.model_validate(mapped_payload)
            return cls.model_validate(payload)
        if hasattr(payload, "model_dump"):
            return cls.model_validate(payload.model_dump())
        raise TypeError(f"Unsupported ToolManifest payload: {type(payload).__name__}")


__all__ = ["ToolManifest"]
