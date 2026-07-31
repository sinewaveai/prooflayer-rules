"""Configuration for the ProofLayer OpenAI Agents integration."""

from dataclasses import dataclass

from ..common.config import RuntimeSecurityConfig


@dataclass
class SecurityConfig(RuntimeSecurityConfig):
    """Runtime security configuration for OpenAI Agents SDK runtimes."""
