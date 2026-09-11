import asyncio

import pytest

import daharness


class DummyEmbeddingModel:
    async def embed(self, text):
        return [0.1, 0.2, 0.3]


class DummyCollection:
    def __init__(self):
        self.items = {}

    def get(self, ids=None, include=None):
        return {"ids": [item_id for item_id in ids if item_id in self.items]}

    def add(self, ids=None, embeddings=None, metadatas=None, documents=None):
        for item_id, item_embedding, item_metadata, item_document in zip(
            ids or [], embeddings or [], metadatas or [], documents or []
        ):
            self.items[item_id] = {
                "embedding": item_embedding,
                "metadata": item_metadata,
                "document": item_document,
            }

    def delete(self, ids=None):
        for item_id in ids or []:
            self.items.pop(item_id, None)


# --- T-002: find_tools must return results sorted by distance ascending ---


class _DistanceQueryCollection:
    """Fake ChromaDB collection whose .query returns a fixed,
    deliberately-unsorted distance ordering so the test can verify that
    find_tools sorts by distance ascending regardless of store order."""

    def __init__(self, rows):
        # rows: list of (id, metadata, document, distance) in the *store*
        # order — intentionally NOT ascending by distance.
        self._rows = rows

    def query(self, query_embeddings=None, n_results=5, **kwargs):
        ids = [r[0] for r in self._rows[:n_results]]
        metadatas = [[r[1] for r in self._rows[:n_results]]]
        documents = [[r[2] for r in self._rows[:n_results]]]
        distances = [[r[3] for r in self._rows[:n_results]]]
        return {
            "ids": [ids],
            "metadatas": metadatas,
            "documents": documents,
            "distances": distances,
        }


def test_find_tools_sorts_by_distance_ascending():
    """T-002: results must be sorted ascending by distance so array
    position == relevance order.  The fake store returns the worst match
    first; find_tools must reorder it."""

    async def _run():
        registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
        registry.embedding_model = DummyEmbeddingModel()

        # Deliberately worst-first: 0.9, 0.3, 0.7
        _meta = lambda: {
            "transport": "brain_dispatch",
            "parameters_json": "{}",
            "external_description": "desc",
            "implementation_path": "some/path",
            "internal_semantics": "semantics",
        }
        rows = [
            ("tool_far", _meta(), "far capability", 0.9),
            ("tool_near", _meta(), "near capability", 0.3),
            ("tool_mid", _meta(), "mid capability", 0.7),
        ]
        registry.collection = _DistanceQueryCollection(rows)

        async def fake_embed(text):
            return [0.1, 0.2, 0.3]

        registry._embed_text = fake_embed

        manifests = await registry.find_tools("some intent", top_k=3)

        assert len(manifests) == 3
        distances = [m.distance for m in manifests]
        assert distances == sorted(distances), (
            f"Distances not ascending: {distances}"
        )
        # Best match (lowest distance) must be first.
        assert manifests[0].module_id == "tool_near"
        assert manifests[0].distance == 0.3
        # Worst match must be last.
        assert manifests[-1].module_id == "tool_far"
        assert manifests[-1].distance == 0.9

    asyncio.run(_run())


def test_register_tool_stores_valid_manifest_once():
    async def _run():
        registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
        registry.embedding_model = DummyEmbeddingModel()
        registry.collection = DummyCollection()

        manifest = daharness.ToolManifest(
            module_id="MOD-001",
            internal_semantic_capability="scan smb for exposures",
            external_sanitized_description="Scan SMB services for exposures",
            parameters={"host": "127.0.0.1"},
            implementation_path="auxiliaries/smb_scanner.py",
            internal_semantics="smb enumeration scanner",
        )

        await registry.register_tool(manifest)
        await registry.register_tool(manifest)

        assert registry.collection.items["MOD-001"]["document"] == "scan smb for exposures"

    asyncio.run(_run())


def test_embed_text_uses_ollama_embed_endpoint(monkeypatch):
    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def post(self, url, json):
            assert url.endswith("/api/embed")
            assert json["model"] == "nomic-embed-text"
            return FakeResponse({"embedding": [0.1, 0.2, 0.3]})

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    monkeypatch.setattr(daharness.httpx, "AsyncClient", FakeAsyncClient)
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    registry.embedding_model = object()

    result = asyncio.run(registry._embed_text("hello"))
    assert result == [0.1, 0.2, 0.3]


def test_resolve_script_path_rejects_outside_workspace():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)

    with pytest.raises(ValueError, match="outside the allowed workspace roots"):
        registry._resolve_script_path("/etc/passwd")


def test_execute_tool_local_script_returns_error_for_invalid_path():
    async def _run():
        registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
        registry.embedding_model = DummyEmbeddingModel()

        manifest = daharness.ToolManifest(
            module_id="MOD-002",
            internal_semantic_capability="file path test",
            external_sanitized_description="Runs a safe file",
            parameters={},
            implementation_path="/etc/passwd",
            internal_semantics="unsafe file path",
        )

        result = await registry.execute_tool(manifest, {})

        assert result["error"]

    asyncio.run(_run())


# --- Secretary (conversational tool agent) ---


def _secretary_registry(monkeypatch=None, executions=None):
    """Registry stub with a scripted model standing in for the LFM secretary."""
    from pydantic_ai.models.function import AgentInfo, FunctionModel
    from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart

    def logic(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        if any(part.part_kind == "tool-call" for message in messages for part in message.parts):
            return ModelResponse(parts=[TextPart("Execution report: done.")])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="execute_tool",
                    args={"tool_id": "MOD-001", "arguments": {"host": "127.0.0.1"}},
                    tool_call_id="call-1",
                )
            ]
        )

    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    registry.embedding_model = DummyEmbeddingModel()
    registry.collection = DummyCollection()
    registry.secretary_model = "test-model"
    registry.confirmer = daharness._cli_confirmer
    registry.secretary = registry._init_secretary_agent(model=FunctionModel(logic))

    if executions is not None:

        async def fake_execute(manifest, arguments, session_id="0"):
            executions.append((manifest.module_id, arguments))
            return {"stdout": "", "stderr": "", "return_code": 0, "status": "Success"}

        registry.execute_tool = fake_execute
    return registry


def _surface_manifest(registry, module_id="MOD-001"):
    deps = daharness.SecretaryDeps(registry=registry)
    deps.record_surfaced([
        daharness.ToolManifest(
            module_id=module_id,
            internal_semantic_capability="scan smb for exposures",
            external_sanitized_description="Scan SMB services for exposures",
            parameters={
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
            implementation_path="auxiliaries/smb_scanner.py",
            internal_semantics="smb enumeration scanner",
        )
    ])
    return deps


def test_run_secretary_approval_executes_surfaced_tool():
    async def _run():
        executions = []
        registry = _secretary_registry(executions=executions)
        deps = _surface_manifest(registry)
        result = await registry.run_secretary(
            "scan smb exposures on 127.0.0.1",
            deps=deps,
            confirmer=lambda summary: True,
        )
        return result, executions

    result, executions = asyncio.run(_run())

    assert executions == [("MOD-001", {"host": "127.0.0.1"})]
    assert result.output == "Execution report: done."


def test_run_secretary_denial_blocks_execution():
    async def _run():
        executions = []
        registry = _secretary_registry(executions=executions)
        deps = _surface_manifest(registry)
        result = await registry.run_secretary(
            "scan smb exposures on 127.0.0.1",
            deps=deps,
            confirmer=lambda summary: False,
        )
        return result, executions

    result, executions = asyncio.run(_run())

    assert executions == []
    assert result.output == "Execution report: done."


def test_run_secretary_refuses_unsurfaced_tool_id():
    async def _run():
        executions = []
        registry = _secretary_registry(executions=executions)
        deps = daharness.SecretaryDeps(registry=registry)  # nothing surfaced: model must search first
        result = await registry.run_secretary(
            "scan smb exposures on 127.0.0.1",
            deps=deps,
            confirmer=lambda summary: True,
        )
        return result, executions

    result, executions = asyncio.run(_run())

    assert executions == []


def test_validate_arguments_flags_schema_mismatch():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = daharness.ToolManifest(
        module_id="MOD-003",
        internal_semantic_capability="scan host",
        external_sanitized_description="Scan a host",
        parameters={"properties": {"host": {"type": "string"}, "port": {"type": "int"}}, "required": ["host"]},
        implementation_path="auxiliaries/smb_scanner.py",
        internal_semantics="host scanner",
    )

    warnings = registry.validate_arguments(manifest, {"hostor": "127.0.0.1"})

    assert any("not in the module schema" in w for w in warnings)
    assert any("Missing required arguments" in w for w in warnings)


# --- Layer 1: typed session handles ---


def _handle_manifest(module_id="MOD-SSH", kinds=("ssh",)):
    """A manifest for a tool that consumes a typed `handle` argument."""
    return daharness.ToolManifest(
        module_id=module_id,
        internal_semantic_capability="run a command on an ssh session",
        external_sanitized_description="Run a command on an ssh session",
        parameters={
            "type": "object",
            "properties": {
                "handle": {"type": "string", "description": "ssh: handle"},
                "command": {"type": "string"},
            },
            "required": ["handle", "command"],
        },
        implementation_path="utils/paramiko_client.py",
        internal_semantics="ssh exec",
        accepted_handle_kinds=kinds,
    )


def test_validate_handle_argument_accepts_correct_namespace():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest()
    assert registry.validate_handle_argument(manifest, {"handle": "ssh:sess-0001"}) is None


def test_validate_handle_argument_rejects_cross_namespace():
    """The core Layer 1 guarantee: an msf: handle must NOT flow into an ssh-only tool."""
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest(kinds=("ssh",))
    reason = registry.validate_handle_argument(manifest, {"handle": "msf:1"})
    assert reason is not None
    assert "msf" in reason
    assert "ssh" in reason
    # And it must point the model at the right tool family.
    assert "interact_session" in reason


def test_validate_handle_argument_rejects_malformed_handle():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest()
    reason = registry.validate_handle_argument(manifest, {"handle": "not-a-handle"})
    assert reason is not None
    assert "valid session handle" in reason


def test_validate_handle_argument_ignores_tools_without_handle_kinds():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest(kinds=())
    # No accepted_handle_kinds -> no validation, even for a bogus value.
    assert registry.validate_handle_argument(manifest, {"handle": "msf:1"}) is None


def test_normalize_handle_argument_renames_legacy_session_id():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest()
    normalized = registry.normalize_handle_argument(
        manifest, {"session_id": "ssh:sess-0001", "command": "id"}
    )
    assert normalized["handle"] == "ssh:sess-0001"
    assert normalized["command"] == "id"
    assert "session_id" in normalized  # legacy key preserved, not dropped


def test_normalize_handle_argument_noop_when_handle_present():
    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    manifest = _handle_manifest()
    normalized = registry.normalize_handle_argument(
        manifest, {"handle": "ssh:sess-0001", "command": "id"}
    )
    assert normalized == {"handle": "ssh:sess-0001", "command": "id"}


def test_run_secretary_rejects_cross_namespace_handle_without_executing():
    """A surfaced ssh-only tool called with an msf: handle must raise ModelRetry
    (so the model is told to use interact_session) and must NEVER reach
    execute_tool. This is the regression test for the session entanglement."""
    from pydantic_ai.models.function import AgentInfo, FunctionModel
    from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart

    def logic(messages, info):
        if any(part.part_kind == "tool-call" for message in messages for part in message.parts):
            return ModelResponse(parts=[TextPart("Execution report: done.")])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="execute_tool",
                    args={"tool_id": "MOD-SSH", "arguments": {"handle": "msf:1", "command": "id"}},
                    tool_call_id="call-1",
                )
            ]
        )

    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    registry.embedding_model = DummyEmbeddingModel()
    registry.collection = DummyCollection()
    registry.secretary_model = "test-model"
    registry.confirmer = daharness._cli_confirmer
    registry.secretary = registry._init_secretary_agent(model=FunctionModel(logic))

    executions = []

    async def fake_execute(manifest, arguments, session_id="0"):
        executions.append((manifest.module_id, arguments))
        return {"stdout": "", "status": "Success"}

    registry.execute_tool = fake_execute

    deps = daharness.SecretaryDeps(registry=registry)
    deps.record_surfaced([_handle_manifest()])

    async def _run():
        return await registry.run_secretary(
            "run id on the session",
            deps=deps,
            confirmer=lambda summary: True,
        )

    result = asyncio.run(_run())
    # The bad handle must have been rejected before execution.
    assert executions == []
    assert result.output == "Execution report: done."


def test_run_secretary_executes_correct_namespace_handle():
    """The positive control: a correct ssh: handle on an ssh-only tool IS executed."""
    from pydantic_ai.models.function import AgentInfo, FunctionModel
    from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart

    def logic(messages, info):
        if any(part.part_kind == "tool-call" for message in messages for part in message.parts):
            return ModelResponse(parts=[TextPart("Execution report: done.")])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="execute_tool",
                    args={"tool_id": "MOD-SSH", "arguments": {"handle": "ssh:sess-0001", "command": "id"}},
                    tool_call_id="call-1",
                )
            ]
        )

    registry = daharness.ToolRegistry.__new__(daharness.ToolRegistry)
    registry.embedding_model = DummyEmbeddingModel()
    registry.collection = DummyCollection()
    registry.secretary_model = "test-model"
    registry.confirmer = daharness._cli_confirmer
    registry.secretary = registry._init_secretary_agent(model=FunctionModel(logic))

    executions = []

    async def fake_execute(manifest, arguments, session_id="0"):
        executions.append((manifest.module_id, arguments))
        return {"stdout": "uid=0", "status": "Success"}

    registry.execute_tool = fake_execute

    deps = daharness.SecretaryDeps(registry=registry)
    deps.record_surfaced([_handle_manifest()])

    async def _run():
        return await registry.run_secretary(
            "run id on the session",
            deps=deps,
            confirmer=lambda summary: True,
        )

    result = asyncio.run(_run())
    assert executions == [("MOD-SSH", {"handle": "ssh:sess-0001", "command": "id"})]
    assert result.output == "Execution report: done."
