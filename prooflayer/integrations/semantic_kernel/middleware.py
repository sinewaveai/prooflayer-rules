"""Security middleware for Semantic Kernel agents and kernels."""

from typing import Optional

from ...detection.engine import DetectionEngine
from ..common.agent_security import AgentSecurity, SecuredAgentRuntime
from .config import SecurityConfig
from .exceptions import BlockedAgentError


class SecurityMiddleware(AgentSecurity):
    """Wrap Semantic Kernel agents and kernels with ProofLayer checks."""

    integration_name = "semantic_kernel"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize Semantic Kernel security middleware."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
            blocked_error_type=BlockedAgentError,
        )

    def wrap_kernel(self, kernel: object) -> SecuredAgentRuntime:
        """Wrap a Semantic Kernel kernel while preserving invocation methods."""
        return self.wrap_agent(kernel)

    def wrap_agent(self, agent: object) -> SecuredAgentRuntime:
        """Wrap a Semantic Kernel agent while preserving invocation methods."""
        return super().wrap_agent(agent)
