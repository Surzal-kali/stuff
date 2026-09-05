from enum import Enum

class TransportType(Enum):
    LOCAL_FILE = "local_file"
    MCP_RPC = "mcp_rpc"
    BRAIN_DISPATCH = "brain_dispatch"

def framework_tool(doc: str = None, transport: TransportType = TransportType.BRAIN_DISPATCH):
    """Decorator to mark a function as a framework tool callable by the Brain."""
    def decorator(func):
        func._is_framework_tool = True
        func._tool_doc = doc or (func.__doc__ or "No description provided.")
        func._transport = transport
        return func
    return decorator
