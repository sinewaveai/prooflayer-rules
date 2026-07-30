"""Shared exceptions for ProofLayer runtime integrations."""


class IntegrationSecurityError(Exception):
    """Base exception for integration security failures."""


class RuntimeBlockedError(IntegrationSecurityError):
    """Raised when an integration blocks runtime execution."""
