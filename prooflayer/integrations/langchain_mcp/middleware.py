"""Security middleware for tools from langchain-mcp-adapters."""

from collections.abc import Iterable
from typing import Any, Optional

from ...detection.engine import DetectionEngine
from ...response.actions import ThreatAction
from ..common.decisions import Decision
from ..common.runtime_proxy import SecuredRuntimeProxy
from ..common.tool_security import RuntimeToolSecurity
from .config import SecurityConfig
from .exceptions import BlockedToolError


class SecurityMiddleware(RuntimeToolSecurity):
    """Wrap LangChain-compatible MCP tools with ProofLayer security checks."""

    integration_name = "langchain_mcp"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize LangChain MCP middleware."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
        )

    def wrap_tools(self, tools: Iterable[Any]) -> list["SecuredLangChainMCPTool"]:
        """Scan and wrap LangChain-compatible tools before agent exposure."""
        return [self.wrap_tool(tool) for tool in tools]

    def wrap_tool(self, tool: Any) -> "SecuredLangChainMCPTool":
        """Scan and wrap one LangChain-compatible tool."""
        tool_name = _tool_name(tool)
        metadata = _tool_metadata(tool)
        decision = self.scan_tool_description(
            tool_name=tool_name,
            description=_tool_description(tool),
            metadata=metadata,
        )
        self._raise_if_blocked(
            decision,
            f"LangChain MCP tool blocked before exposure: {tool_name}",
        )
        return SecuredLangChainMCPTool(tool=tool, middleware=self)

    def scan_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic LangChain MCP input before execution."""
        return self.scan_tool_arguments("langchain_mcp_input", payload, config)

    def scan_output(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic LangChain MCP output after execution."""
        return self.scan_tool_output("langchain_mcp_output", payload, config)

    def _raise_if_blocked(self, decision: Decision, message: str) -> None:
        if decision.action == ThreatAction.BLOCK:
            rules = ", ".join(decision.rule_ids)
            raise BlockedToolError(f"{message} (rules: {rules})")


class SecuredLangChainMCPTool(SecuredRuntimeProxy):
    """Proxy that preserves LangChain tool invocation methods."""

    def __init__(self, tool: Any, middleware: SecurityMiddleware) -> None:
        """Create a secured LangChain MCP tool proxy."""
        super().__init__(target=tool, adapter=middleware)
        self._middleware = middleware
        self._tool_name = _tool_name(tool)
        self._metadata = _tool_metadata(tool)

    def invoke(self, input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Invoke a LangChain tool with argument and output scanning."""
        config = kwargs.get("config")
        payload = _call_payload(input, args, kwargs)
        self._scan_arguments(payload, config)
        result = self.target.invoke(input, *args, **kwargs)
        self._scan_output(result, config)
        return result

    async def ainvoke(self, input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Invoke a LangChain tool asynchronously with scanning."""
        config = kwargs.get("config")
        payload = _call_payload(input, args, kwargs)
        self._scan_arguments(payload, config)
        result = await self.target.ainvoke(input, *args, **kwargs)
        self._scan_output(result, config)
        return result

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run a LangChain tool with argument and output scanning."""
        config = kwargs.get("config")
        payload = _call_payload(None, args, kwargs)
        self._scan_arguments(payload, config)
        result = self.target.run(*args, **kwargs)
        self._scan_output(result, config)
        return result

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Run a LangChain tool asynchronously with scanning."""
        config = kwargs.get("config")
        payload = _call_payload(None, args, kwargs)
        self._scan_arguments(payload, config)
        result = await self.target.arun(*args, **kwargs)
        self._scan_output(result, config)
        return result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call a tool directly with argument and output scanning."""
        config = kwargs.get("config")
        payload = _call_payload(None, args, kwargs)
        self._scan_arguments(payload, config)
        result = self.target(*args, **kwargs)
        self._scan_output(result, config)
        return result

    def _scan_arguments(
        self,
        payload: Any,
        config: Optional[dict[str, Any]],
    ) -> None:
        decision = self._middleware.scan_tool_arguments(
            self._tool_name,
            payload,
            config,
            self._metadata,
        )
        self._middleware._raise_if_blocked(
            decision,
            f"LangChain MCP tool call blocked: {self._tool_name}",
        )

    def _scan_output(
        self,
        output: Any,
        config: Optional[dict[str, Any]],
    ) -> None:
        decision = self._middleware.scan_tool_output(
            self._tool_name,
            output,
            config,
            self._metadata,
        )
        self._middleware._raise_if_blocked(
            decision,
            f"LangChain MCP tool output blocked: {self._tool_name}",
        )


def _tool_name(tool: Any) -> str:
    """Return a stable tool name from LangChain-like tool objects."""
    if isinstance(tool, dict):
        return str(tool.get("name") or "unknown_tool")
    return str(
        getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _tool_description(tool: Any) -> str:
    """Return a searchable tool description from LangChain-like tools."""
    if isinstance(tool, dict):
        return str(tool.get("description") or "")
    return str(getattr(tool, "description", "") or "")


def _tool_metadata(tool: Any) -> dict[str, Any]:
    """Return metadata for audit events from LangChain-like tools."""
    if isinstance(tool, dict):
        return dict(tool.get("metadata") or {})
    metadata = getattr(tool, "metadata", None)
    if isinstance(metadata, dict):
        return dict(metadata)
    return {}


def _call_payload(input: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Normalize positional and keyword tool-call arguments for scanning."""
    payload: dict[str, Any] = {}
    if input is not None:
        payload["input"] = input
    if args:
        payload["args"] = list(args)
    visible_kwargs = {
        key: value
        for key, value in kwargs.items()
        if key not in {"config", "callbacks", "tags", "metadata"}
    }
    if visible_kwargs:
        payload["kwargs"] = visible_kwargs
    return payload or {}
