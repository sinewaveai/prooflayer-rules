"""Exceptions for the ProofLayer Pydantic AI integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the Pydantic AI integration."""


class BlockedAgentError(SecurityException):
    """Raised when Pydantic AI execution is blocked by ProofLayer."""
