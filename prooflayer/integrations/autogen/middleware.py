"""Security middleware for Microsoft AutoGen agents."""

from typing import Optional

from ...detection.engine import DetectionEngine
from ..common.agent_security import AgentSecurity, SecuredAgentRuntime
from .config import SecurityConfig
from .exceptions import BlockedAgentError


class SecurityMiddleware(AgentSecurity):
    """Wrap AutoGen agents with ProofLayer message and tool-call checks."""

    integration_name = "autogen"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize AutoGen security middleware."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
            blocked_error_type=BlockedAgentError,
        )

    def wrap_agent(self, agent: object) -> SecuredAgentRuntime:
        """Wrap an AutoGen agent while preserving invocation methods."""
        return super().wrap_agent(agent)
