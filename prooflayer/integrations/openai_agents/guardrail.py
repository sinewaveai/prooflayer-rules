"""ProofLayer guardrail for OpenAI Agents SDK runtimes."""

from typing import Optional

from ...detection.engine import DetectionEngine
from ..common.agent_security import AgentSecurity, SecuredAgentRuntime
from .config import SecurityConfig
from .exceptions import BlockedAgentError


class ProofLayerGuardrail(AgentSecurity):
    """Wrap OpenAI Agents SDK agents with ProofLayer security checks."""

    integration_name = "openai_agents"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize the OpenAI Agents guardrail."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
            blocked_error_type=BlockedAgentError,
        )

    def wrap_agent(self, agent: object) -> SecuredAgentRuntime:
        """Wrap an OpenAI Agents SDK agent while preserving invocation methods."""
        return super().wrap_agent(agent)
