"""Security middleware for CrewAI crews and agents."""

from typing import Optional

from ...detection.engine import DetectionEngine
from ..common.agent_security import AgentSecurity, SecuredAgentRuntime
from .config import SecurityConfig
from .exceptions import BlockedAgentError


class SecurityMiddleware(AgentSecurity):
    """Wrap CrewAI crews and agents with ProofLayer security checks."""

    integration_name = "crewai"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize CrewAI security middleware."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
            blocked_error_type=BlockedAgentError,
        )

    def wrap_crew(self, crew: object) -> SecuredAgentRuntime:
        """Wrap a CrewAI crew while preserving kickoff methods."""
        return self.wrap_agent(crew)

    def wrap_agent(self, agent: object) -> SecuredAgentRuntime:
        """Wrap a CrewAI agent while preserving invocation methods."""
        return super().wrap_agent(agent)
