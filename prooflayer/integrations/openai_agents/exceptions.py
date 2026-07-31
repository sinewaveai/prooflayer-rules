"""Exceptions for the ProofLayer OpenAI Agents integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the OpenAI Agents integration."""


class BlockedAgentError(SecurityException):
    """Raised when OpenAI Agents execution is blocked by ProofLayer."""
