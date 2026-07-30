"""Configuration for the ProofLayer LlamaIndex integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for LlamaIndex tools and context."""
