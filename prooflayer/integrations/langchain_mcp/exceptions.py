"""Exceptions for the ProofLayer LangChain MCP integration."""

from ..common.exceptions import RuntimeBlockedError


class SecurityException(RuntimeBlockedError):
    """Base exception raised by the LangChain MCP integration."""


class BlockedToolError(SecurityException):
    """Raised when a LangChain MCP tool is blocked by ProofLayer."""
