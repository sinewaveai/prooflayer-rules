"""Shared configuration for ProofLayer runtime integrations."""

from dataclasses import dataclass, field
from typing import Literal, Optional

DetectionAction = Literal["allow", "warn", "block"]
StreamingBlockMode = Literal["raise", "replace"]

_VALID_ACTIONS = {"allow", "warn", "block"}
_VALID_FRAMEWORKS = {"nist_ai_rmf", "eu_ai_act", "soc2", "hipaa"}
_VALID_STREAMING_BLOCK_MODES = {"raise", "replace"}


@dataclass
class RuntimeSecurityConfig:
    """Runtime security configuration shared by ProofLayer integrations."""

    prompt_injection: DetectionAction = "warn"
    jailbreak: DetectionAction = "warn"
    tool_abuse: DetectionAction = "warn"
    tool_poisoning: DetectionAction = "warn"
    command_injection: DetectionAction = "block"
    exfil: DetectionAction = "block"
    scope_drift: DetectionAction = "warn"
    state_manipulation: DetectionAction = "warn"
    multi_turn: DetectionAction = "warn"
    memory_poisoning: DetectionAction = "warn"
    unsafe_handoff: DetectionAction = "warn"
    allowed_tools: Optional[list[str]] = None
    blocked_tools: Optional[list[str]] = None
    allowed_domains: Optional[list[str]] = None
    blocked_domains: Optional[list[str]] = None
    max_tool_calls_per_turn: Optional[int] = None
    compliance_frameworks: list[str] = field(default_factory=list)
    emit_to: list[str] = field(default_factory=lambda: ["stdout"])
    session_id_key: str = "session_id"
    streaming_block_mode: StreamingBlockMode = "raise"
    blocked_token: str = "[BLOCKED]"

    def __post_init__(self) -> None:
        """Validate actions, evidence frameworks, audit sinks, and limits."""
        invalid_actions = {
            category: action
            for category, action in self.category_actions().items()
            if action not in _VALID_ACTIONS
        }
        if invalid_actions:
            details = ", ".join(
                f"{category}={action!r}" for category, action in invalid_actions.items()
            )
            raise ValueError(f"Invalid runtime security action(s): {details}")

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
            if sink in {"stdout", "siem"}:
                continue
            if sink.startswith("logfile:") and sink.removeprefix("logfile:").strip():
                continue
            raise ValueError(f"Unsupported audit sink: {sink!r}")

        if not self.session_id_key:
            raise ValueError("session_id_key must not be empty")

        if self.streaming_block_mode not in _VALID_STREAMING_BLOCK_MODES:
            raise ValueError(
                f"Unsupported streaming_block_mode: {self.streaming_block_mode!r}"
            )

        if not self.blocked_token:
            raise ValueError("blocked_token must not be empty")

        if (
            self.max_tool_calls_per_turn is not None
            and self.max_tool_calls_per_turn < 1
        ):
            raise ValueError("max_tool_calls_per_turn must be positive")

    def category_actions(self) -> dict[str, DetectionAction]:
        """Return detection categories mapped to configured actions."""
        return {
            "prompt_injection": self.prompt_injection,
            "jailbreak": self.jailbreak,
            "tool_abuse": self.tool_abuse,
            "tool_poisoning": self.tool_poisoning,
            "command_injection": self.command_injection,
            "exfil": self.exfil,
            "scope_drift": self.scope_drift,
            "state_manipulation": self.state_manipulation,
            "multi_turn": self.multi_turn,
            "memory_poisoning": self.memory_poisoning,
            "unsafe_handoff": self.unsafe_handoff,
        }
