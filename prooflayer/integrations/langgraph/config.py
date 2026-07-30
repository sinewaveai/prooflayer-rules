"""Configuration for the ProofLayer LangGraph integration."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..common.config import DetectionAction, RuntimeSecurityConfig, StreamingBlockMode


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
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
    streaming_block_mode: StreamingBlockMode = "raise"
    blocked_token: str = "[BLOCKED]"

    def __post_init__(self) -> None:
        """Validate category actions, evidence frameworks, and emit targets."""
        try:
            super().__post_init__()
        except ValueError as exc:
            message = str(exc).replace(
                "Invalid runtime security action(s)",
                "Invalid LangGraph security action(s)",
            )
            raise ValueError(message) from exc

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
