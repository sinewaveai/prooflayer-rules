"""
ProofLayer Runtime Security
============================

Runtime prompt injection firewall for MCP servers.
Detects malicious prompts, kills compromised servers, generates security reports.
"""

from .runtime.wrapper import ProofLayerRuntime
from .detection.engine import DetectionEngine
from .detection.models import ScanResult, DetectionRule
from .detection.scanner import PatternScanner
from .detection.scorer import RiskScorer
from .detection.semantic import SemanticAnalyzer
from .response.actions import ThreatAction, ResponseAction
from .response.killer import ServerKiller
from .runtime.interceptor import MCPInterceptor
from .runtime.middleware import ProofLayerMiddleware

__version__ = "0.1.0"
__author__ = "Sinewave AI"
__license__ = "Apache-2.0"

__all__ = [
    "ProofLayerRuntime",
    "DetectionEngine",
    "DetectionRule",
    "ScanResult",
    "PatternScanner",
    "RiskScorer",
    "SemanticAnalyzer",
    "ThreatAction",
    "ResponseAction",
    "ServerKiller",
    "MCPInterceptor",
    "ProofLayerMiddleware",
]


# Lazy imports for optional dependencies
def __getattr__(name):
    if name == "ProofLayerMCPWrapper":
        from .runtime.mcp_wrapper import ProofLayerMCPWrapper
        return ProofLayerMCPWrapper
    if name == "ProofLayerTransportProxy":
        from .runtime.transport import ProofLayerTransportProxy
        return ProofLayerTransportProxy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
