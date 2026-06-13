"""Security middleware for LangGraph compiled graphs."""

from collections.abc import AsyncIterator, Iterator
from typing import Any, Dict, List, Optional

from ...response.actions import ThreatAction
from .config import SecurityConfig
from .hooks import HookAdapter


class SecurityMiddleware:
    """Wrap a compiled LangGraph with ProofLayer runtime security checks."""

    def __init__(self, config: Optional[SecurityConfig] = None) -> None:
        """Initialize middleware with a validated security configuration."""
        self.config = config or SecurityConfig()
        self._audit_log: List[Dict[str, Any]] = []
        self.hooks = HookAdapter(self)

    def wrap(self, compiled_graph: Any) -> "_SecuredLangGraph":
        """Return a secured proxy around a compiled LangGraph object."""
        return _SecuredLangGraph(compiled_graph=compiled_graph, middleware=self)

    def get_audit_log(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return audit events, optionally filtered by session ID."""
        if session_id is None:
            return list(self._audit_log)
        return [
            event
            for event in self._audit_log
            if event.get("session_id") == session_id
        ]

    def record_event(self, event: Dict[str, Any]) -> None:
        """Append a structured event to the in-memory audit log."""
        self._audit_log.append(dict(event))

    def extract_session_id(
        self,
        config: Optional[Dict[str, Any]] = None,
        payload: Any = None,
    ) -> Optional[str]:
        """Extract a session ID from LangGraph config or state payload."""
        if config:
            configurable = config.get("configurable", {})
            if self.config.session_id_key in configurable:
                return str(configurable[self.config.session_id_key])
            if "thread_id" in configurable:
                return str(configurable["thread_id"])

        if isinstance(payload, dict) and self.config.session_id_key in payload:
            return str(payload[self.config.session_id_key])

        return None

    def scan_input(self, payload: Any) -> ThreatAction:
        """Scan graph input before execution.

        Day 2 provides the public extension point and defaults to ALLOW.
        Concrete detection hooks are wired during Days 3 and 4.
        """
        return ThreatAction.ALLOW

    def scan_output(self, payload: Any) -> ThreatAction:
        """Scan graph output after execution.

        Day 2 provides the public extension point and defaults to ALLOW.
        Concrete detection hooks are wired during Days 3 and 4.
        """
        return ThreatAction.ALLOW


class _SecuredLangGraph:
    """Proxy that preserves the compiled LangGraph invocation interface."""

    def __init__(self, compiled_graph: Any, middleware: SecurityMiddleware) -> None:
        self._compiled_graph = compiled_graph
        self._middleware = middleware

    def __getattr__(self, name: str) -> Any:
        return getattr(self._compiled_graph, name)

    def invoke(self, input: Any, *args: Any, **kwargs: Any) -> Any:
        """Run a synchronous graph invocation with security checks."""
        config = kwargs.get("config")
        self._middleware.hooks.before_node("__graph__", input, config)
        result = self._compiled_graph.invoke(input, *args, **kwargs)
        self._middleware.hooks.after_node("__graph__", result, config)
        return result

    async def ainvoke(self, input: Any, *args: Any, **kwargs: Any) -> Any:
        """Run an asynchronous graph invocation with security checks."""
        config = kwargs.get("config")
        self._middleware.hooks.before_node("__graph__", input, config)
        result = await self._compiled_graph.ainvoke(input, *args, **kwargs)
        self._middleware.hooks.after_node("__graph__", result, config)
        return result

    def stream(self, input: Any, *args: Any, **kwargs: Any) -> Iterator[Any]:
        """Stream graph output with security checks around each chunk."""
        config = kwargs.get("config")
        self._middleware.hooks.before_node("__graph__", input, config)
        for chunk in self._compiled_graph.stream(input, *args, **kwargs):
            self._middleware.hooks.after_node("__graph__", chunk, config)
            yield chunk

    async def astream(self, input: Any, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        """Stream graph output asynchronously with security checks around each chunk."""
        config = kwargs.get("config")
        self._middleware.hooks.before_node("__graph__", input, config)
        async for chunk in self._compiled_graph.astream(input, *args, **kwargs):
            self._middleware.hooks.after_node("__graph__", chunk, config)
            yield chunk
