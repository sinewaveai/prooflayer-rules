"""Evidence record schema for compliance control mappings."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..audit.integrity import chain_hash


@dataclass
class EvidenceRecord:
    """Auditor-facing evidence mapped to one compliance control."""

    framework: str
    control_id: str
    evidence_type: str
    source_event: Dict[str, Any]
    event_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    previous_hash: Optional[str] = None
    evidence_hash: Optional[str] = None

    @classmethod
    def from_event(
        cls,
        framework: str,
        control_id: str,
        evidence_type: str,
        event: Dict[str, Any],
        previous_hash: Optional[str] = None,
    ) -> "EvidenceRecord":
        """Create a hashed evidence record from a runtime event."""
        event_id = str(
            event.get("event_hash")
            or event.get("id")
            or event.get("timestamp")
            or f"{event.get('event_type', 'event')}:{event.get('category', 'unknown')}"
        )
        record = cls(
            framework=framework,
            control_id=control_id,
            evidence_type=evidence_type,
            source_event=dict(event),
            event_id=event_id,
            previous_hash=previous_hash,
        )
        payload = record.to_dict()
        payload.pop("evidence_hash", None)
        record.evidence_hash = chain_hash(payload, previous_hash)
        return record

    def to_dict(self) -> Dict[str, Any]:
        """Return the evidence record as a JSON-serializable dictionary."""
        return asdict(self)
