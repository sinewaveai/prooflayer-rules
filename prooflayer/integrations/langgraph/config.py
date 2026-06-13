"""Configuration for the ProofLayer LangGraph integration."""

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional


DetectionAction = Literal["allow", "warn", "block"]


_VALID_ACTIONS = {"allow", "warn", "block"}
_VALID_FRAMEWORKS = {"nist_ai_rmf", "eu_ai_act", "soc2", "hipaa"}


@dataclass
class SecurityConfig:
    """Runtime security configuration for LangGraph middleware."""

    prompt_injection: DetectionAction = "warn"
    jailbreak: DetectionAction = "warn"
    tool_abuse: DetectionAction = "warn"
    exfil: DetectionAction = "warn"
    scope_drift: DetectionAction = "warn"
    state_manipulation: DetectionAction = "warn"
    multi_turn: DetectionAction = "warn"
    compliance_frameworks: List[str] = field(default_factory=list)
    emit_to: List[str] = field(default_factory=lambda: ["stdout"])
    allowed_tools: Optional[List[str]] = None
    session_id_key: str = "session_id"

    def __post_init__(self) -> None:
        """Validate category actions, evidence frameworks, and emit targets."""
        action_values = self.category_actions()
        invalid_actions = {
            category: action
            for category, action in action_values.items()
            if action not in _VALID_ACTIONS
        }
        if invalid_actions:
            details = ", ".join(
                f"{category}={action!r}" for category, action in invalid_actions.items()
            )
            raise ValueError(f"Invalid LangGraph security action(s): {details}")

        invalid_frameworks = [
            framework
            for framework in self.compliance_frameworks
            if framework not in _VALID_FRAMEWORKS
        ]
        if invalid_frameworks:
            raise ValueError(
                "Unsupported compliance framework(s): "
                + ", ".join(sorted(invalid_frameworks))
            )

        if not self.emit_to:
            raise ValueError("emit_to must include at least one audit sink")

        for sink in self.emit_to:
            if sink == "stdout" or sink == "siem":
                continue
            if sink.startswith("logfile:") and sink.removeprefix("logfile:").strip():
                continue
            raise ValueError(f"Unsupported audit sink: {sink!r}")

        if not self.session_id_key:
            raise ValueError("session_id_key must not be empty")

    def category_actions(self) -> Dict[str, DetectionAction]:
        """Return detection categories mapped to configured actions."""
        return {
            "prompt_injection": self.prompt_injection,
            "jailbreak": self.jailbreak,
            "tool_abuse": self.tool_abuse,
            "exfil": self.exfil,
            "scope_drift": self.scope_drift,
            "state_manipulation": self.state_manipulation,
            "multi_turn": self.multi_turn,
        }
