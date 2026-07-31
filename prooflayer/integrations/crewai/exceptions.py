"""Exceptions for the ProofLayer CrewAI integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the CrewAI integration."""


class BlockedAgentError(SecurityException):
    """Raised when CrewAI execution is blocked by ProofLayer."""
