"""Scope drift detection for agent outputs."""

import re
from dataclasses import dataclass
from typing import Any, List

from .normalizer import normalize_text


@dataclass(frozen=True)
class ScopeDriftFinding:
    """A deterministic scope drift finding."""

    rule_id: str
    severity: str
    message: str
    score: int


class ScopeDriftDetector:
    """Detect output that signals an agent has left its intended scope."""

    _PATTERNS = [
        (
            "scope-drift-ignore-scope",
            "high",
            re.compile(r"\b(ignore|bypass|override)\s+(the\s+)?(scope|policy)\b"),
            "Output indicates scope or policy bypass.",
            25,
        ),
        (
            "scope-drift-unrestricted-help",
            "medium",
            re.compile(r"\b(unrestricted|anything\s+you\s+want|no\s+limits?)\b"),
            "Output indicates unrestricted assistance outside the configured scope.",
            20,
        ),
        (
            "scope-drift-unrelated-task",
            "medium",
            re.compile(r"\b(unrelated|outside\s+the\s+scope|different\s+task)\b"),
            "Output indicates a move to an unrelated task.",
            20,
        ),
    ]

    def detect(self, output: Any) -> List[ScopeDriftFinding]:
        """Return scope drift findings for an output payload."""
        text = normalize_text(str(output))
        findings: List[ScopeDriftFinding] = []
        for rule_id, severity, pattern, message, score in self._PATTERNS:
            if pattern.search(text):
                findings.append(
                    ScopeDriftFinding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        score=score,
                    )
                )
        return findings
