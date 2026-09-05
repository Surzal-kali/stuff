from enum import Enum

class TransportType(Enum):
    LOCAL_FILE = "local_file"
    MCP_RPC = "mcp_rpc"
    BRAIN_DISPATCH = "brain_dispatch"
