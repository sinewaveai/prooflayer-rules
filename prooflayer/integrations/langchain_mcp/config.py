"""Configuration for the ProofLayer LangChain MCP integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for LangChain MCP tools."""
