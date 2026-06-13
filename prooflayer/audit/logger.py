"""Structured audit logger with sha256 chain-of-custody hashes."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO

from .integrity import chain_hash
from .siem import to_siem_event


@dataclass
class AuditEvent:
    """A single audit event suitable for runtime security evidence."""

    session_id: str
    rule_id: str
    severity: str
    decision: str
    evidence_snippet: str
    event_type: str = "detection"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "prooflayer"
    metadata: Dict[str, Any] = field(default_factory=dict)
    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return the event as a dictionary."""
        return asdict(self)


class AuditLogger:
    """Emit structured audit events to stdout, JSONL, or SIEM sinks."""

    def __init__(
        self,
        emit_to: Optional[Iterable[str]] = None,
        stream: Optional[TextIO] = None,
    ) -> None:
        """Create an audit logger with configured output sinks."""
        self.emit_to = list(emit_to or ["stdout"])
        self.stream = stream
        self.events: List[AuditEvent] = []
        self._previous_hash: Optional[str] = None

    @property
    def previous_hash(self) -> Optional[str]:
        """Return the latest event hash in the chain."""
        return self._previous_hash

    def log(self, event: AuditEvent) -> AuditEvent:
        """Hash, store, and emit an audit event."""
        event.previous_hash = self._previous_hash
        payload = event.to_dict()
        payload.pop("event_hash", None)
        event.event_hash = chain_hash(payload, self._previous_hash)
        self._previous_hash = event.event_hash
        self.events.append(event)
        self._emit(event)
        return event

    def _emit(self, event: AuditEvent) -> None:
        for sink in self.emit_to:
            if sink == "stdout":
                self._write_stdout(event)
            elif sink == "siem":
                self._write_json(to_siem_event(event.to_dict()))
            elif sink.startswith("logfile:"):
                self._write_jsonl(Path(sink.removeprefix("logfile:")), event)
            else:
                raise ValueError(f"Unsupported audit sink: {sink!r}")

    def _write_stdout(self, event: AuditEvent) -> None:
        message = (
            f"[ProofLayer] {event.decision} {event.rule_id} "
            f"session={event.session_id} severity={event.severity} "
            f"hash={event.event_hash}"
        )
        if self.stream:
            self.stream.write(message + "\n")
        else:
            print(message)

    def _write_json(self, payload: Dict[str, Any]) -> None:
        message = json.dumps(payload, sort_keys=True, default=str)
        if self.stream:
            self.stream.write(message + "\n")
        else:
            print(message)

    def _write_jsonl(self, path: Path, event: AuditEvent) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
