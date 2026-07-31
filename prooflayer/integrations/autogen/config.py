"""Configuration for the ProofLayer AutoGen integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for AutoGen agent conversations."""
