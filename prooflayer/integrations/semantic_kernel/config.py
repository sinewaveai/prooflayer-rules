"""Configuration for the ProofLayer Semantic Kernel integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for Semantic Kernel agents and kernels."""
