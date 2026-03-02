"""Detection models and dataclasses."""

import re
import logging
from typing import Optional, List, Dict, Any, Iterator, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """A single detection rule."""
    id: str
    severity: str  # "low", "medium", "high", "critical"
    message: str
    pattern: str
    score: int
    category: str
    owasp: list = field(default_factory=list)
    compiled_pattern: Optional[re.Pattern] = None

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            logger.warning(f"Failed to compile pattern for rule {self.id}: {e}")
            self.compiled_pattern = None


@dataclass
class ScanResult:
    """Result of a detection engine scan."""
    score: int
    level: str  # "SAFE", "SUSPICIOUS", "THREAT"
    action: str  # "ALLOW", "WARN", "BLOCK"
    matched_rules: List[DetectionRule] = field(default_factory=list)
    scoring_breakdown: Dict[str, int] = field(default_factory=dict)
    tool_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    latency_ms: float = 0.0
    owasp_mapping: List[str] = field(default_factory=list)

    def __iter__(self) -> Iterator[Tuple[int, List[DetectionRule]]]:
        """Backwards compatibility: allows `score, rules = engine.scan(...)`."""
        yield self.score
        yield self.matched_rules
