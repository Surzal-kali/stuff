from enum import Enum

class TransportType(Enum):
    LOCAL_FILE = "local_file"
    MCP_RPC = "mcp_rpc"
    BRAIN_DISPATCH = "brain_dispatch"

def framework_tool(
    doc: str ,
    transport: TransportType = TransportType.BRAIN_DISPATCH,
    accepted_handle_kinds=None,
    next_hints=None,
    tags=None,
    result_digest=None,
):
    """Decorator to mark a function as a framework tool callable by the Brain.

    ``accepted_handle_kinds`` (optional iterable of strings, e.g. ``["ssh"]``)
    declares which typed session handle kinds this tool consumes.  When set,
    the registry validates any ``handle`` argument's kind against this set
    *before* execution and, on mismatch, raises a ``ModelRetry`` pointing the
    model at the right tool instead of letting the call die inside the tool
    body.  See ``utils/handles.py`` for the kind taxonomy.  Tools that do not
    take a session handle simply omit it.

    ``next_hints`` (optional iterable of strings) provides curated next-action
    suggestions surfaced in the manifest so the secretary model knows what to
    call after this tool succeeds.  Examples:
    ``next_hints=["psexec_exec with -hashes :<NTLM>"]``.

    ``tags`` (optional iterable of category strings, e.g. ``["web.fuzz"]``)
    assigns this tool to one or more categories from the canonical vocabulary
    in ``daharness/tool_tags.py`` (CANONICAL_TAGS).  Tags are appended to the
    embedded capability text ("Categories: ...") so semantic searches that use
    category language surface the tool, and they persist in the registry
    metadata + describe_manifest output.  Decorator tags win over the bulk
    TOOL_TAGS map (daharness/tool_tags.py) for the same tool id.
    ``result_digest`` (optional callable) registers a per-tool digest adapter
    used by the result projection layer (utils/result_projection.py).  When
    ``result_mode='digest'`` is requested, the adapter receives the raw tool
    result and returns ``{"summary": str, "row_hint_format": str}`` — a
    compact, structurally-honest digest that replaces the full output in the
    model's context.  The full output is stored in scratch and retrievable
    via ``scratch_search``.  Tools without an adapter fall back to a naive
    head+count preview.  See RFC 2026-10-01.
    """
    def decorator(func):
        func._is_framework_tool = True
        func._tool_doc = doc or (func.__doc__ or "No description provided.")
        func._transport = transport
        func._accepted_handle_kinds = tuple(accepted_handle_kinds) if accepted_handle_kinds else ()
        func._next_hints = tuple(next_hints) if next_hints else ()
        func._tool_tags = tuple(tags) if tags else ()
        func._result_digest = result_digest
        # Register the adapter immediately so the projection layer can find
        # it by tool_id at projection time.  The tool_id for a decorated
        # function is ``module.qualname`` (set during discovery); for methods
        # it's ``module.Class.method``.  We register with a provisional key
        # here and the registry's discovery pass re-registers under the
        # exact tool_id once known.  The provisional key uses __module__
        # + __qualname__ which matches the discovery construction for
        # module-level functions.
        if result_digest is not None:
            try:
                from utils.result_projection import register_digest_adapter
                provisional_id = f"{func.__module__}.{func.__qualname__}"
                register_digest_adapter(provisional_id, result_digest)
            except ImportError:
                pass  # result_projection not importable yet (boot ordering)
        return func
    return decorator
