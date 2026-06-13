"""State manipulation detection for LangGraph workflows."""

import re
from dataclasses import dataclass
from typing import Any, Dict, List

from .normalizer import normalize_text


@dataclass(frozen=True)
class StateManipulationFinding:
    """A deterministic state manipulation finding."""

    rule_id: str
    severity: str
    message: str
    score: int


class StateManipulationDetector:
    """Detect adversarial writes to sensitive LangGraph state fields."""

    _SENSITIVE_KEYS = {
        "system_prompt",
        "developer_prompt",
        "system_instructions",
        "security_policy",
        "memory",
    }
    _TEXT_PATTERNS = [
        (
            "state-manipulation-overwrite-system",
            "critical",
            re.compile(r"\b(overwrite|replace|modify)\s+(the\s+)?system\s+prompt\b"),
            "State update attempts to overwrite the system prompt.",
            35,
        ),
        (
            "state-manipulation-memory-poisoning",
            "high",
            re.compile(r"\b(poison|rewrite|replace)\s+(memory|conversation\s+history)\b"),
            "State update attempts to poison memory or conversation history.",
            30,
        ),
    ]

    def detect(self, state_update: Dict[str, Any]) -> List[StateManipulationFinding]:
        """Return state manipulation findings for a state update."""
        findings: List[StateManipulationFinding] = []
        for key in state_update:
            if key in self._SENSITIVE_KEYS:
                findings.append(
                    StateManipulationFinding(
                        rule_id="state-manipulation-sensitive-key",
                        severity="critical",
                        message=f"State update writes sensitive key {key!r}.",
                        score=35,
                    )
                )

        text = normalize_text(str(state_update))
        for rule_id, severity, pattern, message, score in self._TEXT_PATTERNS:
            if pattern.search(text):
                findings.append(
                    StateManipulationFinding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        score=score,
                    )
                )
        return findings
