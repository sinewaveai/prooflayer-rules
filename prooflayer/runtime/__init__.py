"""Runtime MCP interception and wrapping."""

from .wrapper import ProofLayerRuntime
from .interceptor import MCPInterceptor
from .middleware import ProofLayerMiddleware

__all__ = [
    "ProofLayerRuntime",
    "MCPInterceptor",
    "ProofLayerMiddleware",
]

# Lazy imports for optional dependencies
def __getattr__(name):
    if name == "ProofLayerMCPWrapper":
        from .mcp_wrapper import ProofLayerMCPWrapper
        return ProofLayerMCPWrapper
    if name == "ProofLayerTransportProxy":
        from .transport import ProofLayerTransportProxy
        return ProofLayerTransportProxy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
