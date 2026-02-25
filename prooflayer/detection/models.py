"""Detection models and dataclasses."""

import re
import logging
from typing import Optional
from dataclasses import dataclass

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
    compiled_pattern: Optional[re.Pattern] = None

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            logger.warning(f"Failed to compile pattern for rule {self.id}: {e}")
            self.compiled_pattern = None
