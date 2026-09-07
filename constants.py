from enum import Enum

class TransportType(Enum):
    LOCAL_FILE = "local_file"
    MCP_RPC = "mcp_rpc"
    BRAIN_DISPATCH = "brain_dispatch"

def framework_tool(
    doc: str ,
    transport: TransportType = TransportType.BRAIN_DISPATCH,
    accepted_handle_kinds=None,
):
    """Decorator to mark a function as a framework tool callable by the Brain.

    ``accepted_handle_kinds`` (optional iterable of strings, e.g. ``["ssh"]``)
    declares which typed session handle kinds this tool consumes.  When set,
    the registry validates any ``handle`` argument's kind against this set
    *before* execution and, on mismatch, raises a ``ModelRetry`` pointing the
    model at the right tool instead of letting the call die inside the tool
    body.  See ``utils/handles.py`` for the kind taxonomy.  Tools that do not
    take a session handle simply omit it.
    """
    def decorator(func):
        func._is_framework_tool = True
        func._tool_doc = doc or (func.__doc__ or "No description provided.")
        func._transport = transport
        func._accepted_handle_kinds = tuple(accepted_handle_kinds) if accepted_handle_kinds else ()
        return func
    return decorator
