"""Exceptions for the ProofLayer LlamaIndex integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the LlamaIndex integration."""


class BlockedToolError(SecurityException):
    """Raised when a LlamaIndex tool or context item is blocked."""
