"""Runtime adapter protocol for ProofLayer integrations."""

from typing import Any, Optional, Protocol

from .decisions import Decision


class IntegrationAdapter(Protocol):
    """Protocol implemented by framework-specific ProofLayer adapters."""

    integration_name: str

    def wrap(self, target: Any) -> Any:
        """Return a protected runtime object for the target."""

    def scan_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect runtime input before execution."""

    def scan_output(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect runtime output after execution."""

    def get_audit_log(
        self,
        session_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return audit events, optionally filtered by session ID."""
