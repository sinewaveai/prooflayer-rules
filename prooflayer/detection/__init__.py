"""Threat detection engine."""

from .models import DetectionRule, ScanResult
from .engine import DetectionEngine
from .detector_client import ExternalDetectorClient, apply_detector_result
from .rules import RuleLoadError
from .normalizer import normalize_text, flatten_arguments
from .scanner import PatternScanner
from .scorer import RiskScorer
from .semantic import SemanticAnalyzer
from .scope_drift import ScopeDriftDetector, ScopeDriftFinding
from .state_manipulation import StateManipulationDetector, StateManipulationFinding
from .multi_turn import MultiTurnDetector, MultiTurnFinding

__all__ = [
    "DetectionEngine",
    "ExternalDetectorClient",
    "DetectionRule",
    "ScanResult",
    "RuleLoadError",
    "PatternScanner",
    "RiskScorer",
    "SemanticAnalyzer",
    "ScopeDriftDetector",
    "ScopeDriftFinding",
    "StateManipulationDetector",
    "StateManipulationFinding",
    "MultiTurnDetector",
    "MultiTurnFinding",
    "normalize_text",
    "flatten_arguments",
    "apply_detector_result",
]
