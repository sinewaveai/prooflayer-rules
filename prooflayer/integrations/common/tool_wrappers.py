"""Shared callable tool proxies for agent-framework integrations."""

from __future__ import annotations

from typing import Any, Optional

from ...response.actions import ThreatAction
from .runtime_proxy import SecuredRuntimeProxy
from .tool_security import RuntimeToolSecurity


class SecuredCallableTool(SecuredRuntimeProxy):
    """Proxy for callable framework tools with argument and output scanning."""

    def __init__(self, tool: Any, security: RuntimeToolSecurity) -> None:
        """Create a secured callable tool proxy."""
        super().__init__(target=tool, adapter=security)
        self._security = security
        self._tool_name = _tool_name(tool)
        self._metadata = _tool_metadata(tool)
        decision = self._security.scan_tool_description(
            tool_name=self._tool_name,
            description=_tool_description(tool),
            metadata=self._metadata,
        )
        self._raise_if_blocked(
            decision, f"Tool blocked before exposure: {self._tool_name}"
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call a secured tool with input and output scanning."""
        config = _config_from_kwargs(kwargs)
        payload = _call_payload(args, kwargs)
        decision = self._security.scan_tool_arguments(
            self._tool_name,
            payload,
            config=config,
            metadata=self._metadata,
        )
        self._raise_if_blocked(decision, f"Tool call blocked: {self._tool_name}")
        result = self.target(*args, **kwargs)
        output_decision = self._security.scan_tool_output(
            self._tool_name,
            result,
            config=config,
            metadata=self._metadata,
        )
        self._raise_if_blocked(
            output_decision, f"Tool output blocked: {self._tool_name}"
        )
        return result

    def _raise_if_blocked(self, decision: Any, message: str) -> None:
        if decision.action == ThreatAction.BLOCK:
            rules = ", ".join(decision.rule_ids)
            raise RuntimeError(f"{message} (rules: {rules})")


def _tool_name(tool: Any) -> str:
    """Return a stable tool name from common framework tool shapes."""
    if isinstance(tool, dict):
        return str(tool.get("name") or "unknown_tool")
    return str(
        getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _tool_description(tool: Any) -> str:
    """Return a searchable tool description from common tool shapes."""
    if isinstance(tool, dict):
        return str(tool.get("description") or "")
    return str(
        getattr(tool, "description", None) or getattr(tool, "__doc__", None) or ""
    )


def _tool_metadata(tool: Any) -> dict[str, Any]:
    """Return audit metadata from common framework tool shapes."""
    if isinstance(tool, dict):
        return dict(tool.get("metadata") or {})
    metadata = getattr(tool, "metadata", None)
    return dict(metadata) if isinstance(metadata, dict) else {}


def _call_payload(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Normalize callable tool arguments for scanning."""
    payload: dict[str, Any] = {}
    if args:
        payload["args"] = list(args)
    visible_kwargs = {
        key: value
        for key, value in kwargs.items()
        if key not in {"config", "callbacks", "tags", "metadata"}
    }
    if visible_kwargs:
        payload["kwargs"] = visible_kwargs
    return payload


def _config_from_kwargs(kwargs: dict[str, Any]) -> Optional[dict[str, Any]]:
    config = kwargs.get("config")
    return config if isinstance(config, dict) else None
