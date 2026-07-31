"""Configuration for the ProofLayer Pydantic AI integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for Pydantic AI agents."""
