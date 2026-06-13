"""Exceptions raised by the ProofLayer LangGraph integration."""


class SecurityException(Exception):
    """Base exception for LangGraph runtime security failures."""


class BlockedError(SecurityException):
    """Raised when LangGraph middleware blocks execution."""
