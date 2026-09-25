"""Unit tests for daharness.preflight — the deterministic pre-dispatch gate.

Born from the 2026-09-20 fuzz incident (malformed tool calls hung until
BRAIN_DISPATCH_TIMEOUT). These tests pin the fail-fast contract: bad shape
in, structured Rejection envelope out, milliseconds, no I/O, no dispatch.
"""

import asyncio
import json

from daharness import preflight
from daharness.executor import _new_registry
from daharness.models import ToolManifest


def _manifest(schema=None, module_id="utils.test.tool"):
    return ToolManifest(
        module_id=module_id,
        internal_semantic_capability="test capability",
        external_sanitized_description="test tool",
        implementation_path="utils/test.py",
        internal_semantics="test semantics",
        parameters=schema or {},
    )


_PROBE_SCHEMA = {
    "type": "object",
    "properties": {
        "targets": {"type": "string"},
        "ports": {"type": "string"},
        "timeout": {"type": "number"},
        "insecure": {"type": "boolean"},
    },
    "required": ["targets"],
}


def test_valid_args_pass():
    args, rej = preflight.normalize_arguments(
        json.dumps({"targets": "192.168.90.114", "ports": "80", "timeout": 2})
    )
    assert rej is None
    assert args["targets"] == "192.168.90.114"
    assert args["timeout"] == 2


def test_dict_passthrough():
    args, rej = preflight.normalize_arguments({"targets": "x"})
    assert rej is None
    assert args == {"targets": "x"}


def test_none_args_ok():
    args, rej = preflight.normalize_arguments(None)
    assert rej is None
    assert args == {}


def test_non_json_string_rejected():
    args, rej = preflight.normalize_arguments("not-json")
    assert args is None
    assert preflight.is_rejection(rej)
    assert "not valid JSON" in rej["error"]


def test_scalar_arguments_rejected():
    args, rej = preflight.normalize_arguments("123")
    assert args is None
    assert preflight.is_rejection(rej)
    assert "JSON object" in rej["error"]


def test_underscore_raw_payload_rejected():
    args, rej = preflight.normalize_arguments({"_raw": "garbage"})
    assert args is None
    assert preflight.is_rejection(rej)


def test_oversized_string_value_rejected(monkeypatch):
    monkeypatch.setattr(preflight, "MAX_ARG_STR_LEN", 16)
    args, rej = preflight.normalize_arguments({"targets": "A" * 64})
    assert args is None
    assert preflight.is_rejection(rej)
    assert "too large" in rej["error"]


def test_unknown_key_rejected():
    rej = preflight.validate_against_manifest(
        {"targets": "x", "bogus_key": "1"}, _manifest(_PROBE_SCHEMA)
    )
    assert preflight.is_rejection(rej)
    assert "bogus_key" in rej["error"]
    assert "targets" in rej["accepted_keys"]


def test_missing_required_rejected():
    rej = preflight.validate_against_manifest(
        {"ports": "80"}, _manifest(_PROBE_SCHEMA)
    )
    assert preflight.is_rejection(rej)
    assert "targets" in rej["error"]
    assert "targets" in rej["required"]


def test_empty_string_required_arg_accepted():
    """F-032 regression (2026-09-25): a required string supplied as '' is
    DATA, not absence — db_connect(password: "") (empty-password credential
    probe) must pass preflight.  Only None / empty containers are missing."""
    _db_schema = {
        "type": "object",
        "properties": {
            "db_type": {"type": "string"},
            "host": {"type": "string"},
            "password": {"type": "string"},
        },
        "required": ["db_type", "host", "password"],
    }
    assert preflight.validate_against_manifest(
        {"db_type": "mysql", "host": "1.2.3.4", "password": ""},
        _manifest(_db_schema),
    ) is None
    # Whitespace-only strings are data too (real passwords can be ' ').
    assert preflight.validate_against_manifest(
        {"db_type": "mysql", "host": "1.2.3.4", "password": " "},
        _manifest(_db_schema),
    ) is None
    # Absent and None are still missing.
    rej = preflight.validate_against_manifest(
        {"db_type": "mysql", "host": "1.2.3.4"}, _manifest(_db_schema)
    )
    assert preflight.is_rejection(rej)
    rej = preflight.validate_against_manifest(
        {"db_type": "mysql", "host": "1.2.3.4", "password": None},
        _manifest(_db_schema),
    )
    assert preflight.is_rejection(rej)


def test_enum_violation_rejected():
    schema = {
        "type": "object",
        "properties": {
            "category": {"type": "string", "enum": ["exploit", "auxiliary"]}
        },
        "required": ["category"],
    }
    rej = preflight.validate_against_manifest(
        {"category": "post"}, _manifest(schema)
    )
    assert preflight.is_rejection(rej)
    assert "must be one of" in rej["error"]


def test_bool_coercion_passes():
    rej = preflight.validate_against_manifest(
        {"targets": "x", "insecure": "true"}, _manifest(_PROBE_SCHEMA)
    )
    assert rej is None


def test_open_schema_manifest_skips_unknown_check():
    rej = preflight.validate_against_manifest({"anything": 1}, _manifest({}))
    assert rej is None


def test_execute_tool_gate_rejects_before_dispatch():
    """The executor gate must return the Rejection envelope without touching
    any transport (Brain socket or in-process launch) for malformed args."""

    async def _run():
        registry = _new_registry()
        return await registry.execute_tool(
            _manifest(_PROBE_SCHEMA), "not-json", session_id="0"
        )

    result = asyncio.run(_run())
    assert preflight.is_rejection(result)
    assert result["phase"] == "preflight"