"""Exceptions for the ProofLayer Semantic Kernel integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the Semantic Kernel integration."""


class BlockedAgentError(SecurityException):
    """Raised when Semantic Kernel execution is blocked by ProofLayer."""
