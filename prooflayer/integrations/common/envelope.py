"""Security envelope model for runtime integration events."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass(frozen=True)
class SecurityEnvelope:
    """Normalize runtime activity before ProofLayer detection."""

    integration: str
    event_type: str
    payload: Any
    session_id: Optional[str] = None
    actor: Optional[str] = None
    tool_name: Optional[str] = None
    output: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return asdict(self)


def extract_config_session_id(
    session_id_key: str,
    config: Optional[dict[str, Any]] = None,
    payload: Any = None,
) -> Optional[str]:
    """Extract a session ID from runtime config or payload conventions."""
    if config:
        configurable = config.get("configurable", {})
        if session_id_key in configurable:
            return str(configurable[session_id_key])
        if "thread_id" in configurable:
            return str(configurable["thread_id"])

    if isinstance(payload, dict) and session_id_key in payload:
        return str(payload[session_id_key])

    return None
