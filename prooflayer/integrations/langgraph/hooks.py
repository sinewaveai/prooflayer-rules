"""Hook adapters for LangGraph runtime security events."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, TYPE_CHECKING

from ...response.actions import ThreatAction

if TYPE_CHECKING:
    from .middleware import SecurityMiddleware


@dataclass(frozen=True)
class HookEvent:
    """Structured event emitted by LangGraph security hooks."""

    event_type: str
    node_name: str
    payload: Any
    decision: str
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Return the hook event as a JSON-serializable dictionary."""
        return asdict(self)


class HookAdapter:
    """Adapt LangGraph node, tool, and state activity into security events."""

    def __init__(self, middleware: "SecurityMiddleware") -> None:
        """Create a hook adapter bound to a middleware instance."""
        self.middleware = middleware

    def before_node(
        self,
        node_name: str,
        state: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Run before a node or graph invocation executes."""
        decision = self.middleware.scan_input(state, config)
        self._record("before_node", node_name, state, decision, config)
        return decision

    def after_node(
        self,
        node_name: str,
        output: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Run after a node or graph invocation produces output."""
        decision = self.middleware.scan_output(output, config)
        self._record("after_node", node_name, output, decision, config)
        return decision

    def on_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Run before a LangGraph-managed tool call executes."""
        payload = {"tool_name": tool_name, "arguments": arguments}
        decision = self.middleware.scan_input(payload, config)
        self._record("tool_call", tool_name, payload, decision, config)
        return decision

    def on_state_update(
        self,
        node_name: str,
        state_update: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Run when LangGraph state is updated."""
        decision = self.middleware.scan_input(state_update, config)
        self._record("state_update", node_name, state_update, decision, config)
        return decision

    def _record(
        self,
        event_type: str,
        node_name: str,
        payload: Any,
        decision: ThreatAction,
        config: Optional[Dict[str, Any]],
    ) -> None:
        session_id = self.middleware.extract_session_id(config, payload)
        event = HookEvent(
            event_type=event_type,
            node_name=node_name,
            payload=payload,
            decision=decision.value,
            session_id=session_id,
            metadata={"source": "langgraph"},
        )
        self.middleware.record_event(event.to_dict())


def before_node(
    middleware: "SecurityMiddleware",
    node_name: str,
    state: Any,
    config: Optional[Dict[str, Any]] = None,
) -> ThreatAction:
    """Invoke the before-node hook for a middleware instance."""
    return middleware.hooks.before_node(node_name, state, config)


def after_node(
    middleware: "SecurityMiddleware",
    node_name: str,
    output: Any,
    config: Optional[Dict[str, Any]] = None,
) -> ThreatAction:
    """Invoke the after-node hook for a middleware instance."""
    return middleware.hooks.after_node(node_name, output, config)


def on_tool_call(
    middleware: "SecurityMiddleware",
    tool_name: str,
    arguments: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> ThreatAction:
    """Invoke the tool-call hook for a middleware instance."""
    return middleware.hooks.on_tool_call(tool_name, arguments, config)


def on_state_update(
    middleware: "SecurityMiddleware",
    node_name: str,
    state_update: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> ThreatAction:
    """Invoke the state-update hook for a middleware instance."""
    return middleware.hooks.on_state_update(node_name, state_update, config)
