"""Configuration for the ProofLayer CrewAI integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for CrewAI crews and agents."""
