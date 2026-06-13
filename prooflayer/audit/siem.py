"""SIEM-compatible audit event formatting."""

from typing import Any, Dict


def to_siem_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an audit event into a Splunk-compatible JSON shape."""
    return {
        "time": event.get("timestamp"),
        "host": "prooflayer",
        "source": "prooflayer-runtime",
        "sourcetype": "prooflayer:audit",
        "event": event,
    }
