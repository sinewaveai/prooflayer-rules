"""Exceptions for the ProofLayer AutoGen integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the AutoGen integration."""


class BlockedAgentError(SecurityException):
    """Raised when AutoGen execution is blocked by ProofLayer."""
