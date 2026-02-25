"""
ProofLayer Runtime Security
============================

Runtime prompt injection firewall for MCP servers.
Detects malicious prompts, kills compromised servers, generates security reports.

Built for SUSE Multi-Linux Manager and enterprise Kubernetes deployments.
"""

from .runtime.wrapper import ProofLayerRuntime
from .detection.engine import DetectionEngine
from .response.actions import ThreatAction, ResponseAction

__version__ = "0.1.0"
__author__ = "Sinewave AI"
__license__ = "MIT"

__all__ = [
    "ProofLayerRuntime",
    "DetectionEngine",
    "ThreatAction",
    "ResponseAction",
]
