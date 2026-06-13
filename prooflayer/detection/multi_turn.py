"""Multi-turn attack detection for LangGraph sessions."""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, List

from .normalizer import normalize_text


@dataclass(frozen=True)
class MultiTurnFinding:
    """A deterministic multi-turn attack finding."""

    rule_id: str
    severity: str
    message: str
    score: int


class MultiTurnDetector:
    """Detect slow-burn attacks accumulated across conversation turns."""

    _SUSPICIOUS_PATTERN = re.compile(
        r"\b(remember\s+this|for\s+later|next\s+turn|store\s+this|"
        r"forget\s+safety|ignore\s+instructions\s+later)\b"
    )

    def __init__(self) -> None:
        """Create an empty per-session signal store."""
        self._signals: DefaultDict[str, List[str]] = defaultdict(list)

    def detect(self, session_id: str, payload: Any) -> List[MultiTurnFinding]:
        """Return multi-turn findings for a session and payload."""
        text = normalize_text(str(payload))
        if self._SUSPICIOUS_PATTERN.search(text):
            self._signals[session_id].append(text)

        if len(self._signals[session_id]) >= 2:
            return [
                MultiTurnFinding(
                    rule_id="multi-turn-slow-burn-injection",
                    severity="high",
                    message="Multiple suspicious turns indicate a slow-burn injection.",
                    score=30,
                )
            ]
        return []

    def signal_count(self, session_id: str) -> int:
        """Return the number of suspicious turns seen for a session."""
        return len(self._signals[session_id])
