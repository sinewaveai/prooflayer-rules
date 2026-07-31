"""Security middleware for Pydantic AI agents."""

from typing import Optional

from ...detection.engine import DetectionEngine
from ..common.agent_security import AgentSecurity, SecuredAgentRuntime
from .config import SecurityConfig
from .exceptions import BlockedAgentError


class SecurityMiddleware(AgentSecurity):
    """Wrap Pydantic AI agents with ProofLayer security checks."""

    integration_name = "pydantic_ai"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize Pydantic AI security middleware."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
            blocked_error_type=BlockedAgentError,
        )

    def wrap_agent(self, agent: object) -> SecuredAgentRuntime:
        """Wrap a Pydantic AI agent while preserving invocation methods."""
        return super().wrap_agent(agent)
