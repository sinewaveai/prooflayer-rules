"""Shared audit helpers for runtime integrations."""

from copy import deepcopy
from typing import Any, Optional

from ...audit.integrity import chain_hash


class AuditEventRecorder:
    """Store audit events with a sha256 chain-of-custody hash."""

    def __init__(self) -> None:
        """Create an empty audit event recorder."""
        self._events: list[dict[str, Any]] = []
        self._previous_hash: Optional[str] = None

    @property
    def previous_hash(self) -> Optional[str]:
        """Return the previous event hash in the audit chain."""
        return self._previous_hash

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append, hash, and return a copy of an audit event."""
        stored = deepcopy(event)
        stored.setdefault("previous_hash", self._previous_hash)
        payload = deepcopy(stored)
        payload.pop("event_hash", None)
        payload.pop("hash", None)
        event_hash = chain_hash(payload, self._previous_hash)
        stored["event_hash"] = event_hash
        stored["hash"] = f"sha256:{event_hash}"
        self._previous_hash = event_hash
        self._events.append(stored)
        return deepcopy(stored)

    def list(self, session_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Return stored audit events, optionally filtered by session ID."""
        if session_id is None:
            return deepcopy(self._events)
        return [
            deepcopy(event)
            for event in self._events
            if event.get("session_id") == session_id
        ]
