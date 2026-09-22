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
    """
    def decorator(func):
        func._is_framework_tool = True
        func._tool_doc = doc or (func.__doc__ or "No description provided.")
        func._transport = transport
        func._accepted_handle_kinds = tuple(accepted_handle_kinds) if accepted_handle_kinds else ()
        func._next_hints = tuple(next_hints) if next_hints else ()
        func._tool_tags = tuple(tags) if tags else ()
        return func
    return decorator
