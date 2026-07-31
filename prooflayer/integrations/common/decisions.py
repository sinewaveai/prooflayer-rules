"""Decision models shared by ProofLayer runtime integrations."""

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from ...response.actions import ThreatAction


@dataclass(frozen=True)
class Decision:
    """A normalized security decision returned by integration adapters."""

    action: ThreatAction
    category: Optional[str] = None
    risk_score: int = 0
    rule_ids: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls) -> "Decision":
        """Return a reusable ALLOW decision."""
        return cls(action=ThreatAction.ALLOW)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        payload = asdict(self)
        payload["action"] = self.action.value
        return payload
