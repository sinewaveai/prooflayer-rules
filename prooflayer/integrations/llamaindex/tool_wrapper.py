"""Security wrapper for LlamaIndex tools and retrieved context."""

from collections.abc import Iterable
from typing import Any, Optional

from ...detection.engine import DetectionEngine
from ...response.actions import ThreatAction
from ..common.decisions import Decision
from ..common.runtime_proxy import SecuredRuntimeProxy
from ..common.tool_security import RuntimeToolSecurity
from .config import SecurityConfig
from .exceptions import BlockedToolError


class ProofLayerToolWrapper(RuntimeToolSecurity):
    """Wrap LlamaIndex tools with ProofLayer runtime security checks."""

    integration_name = "llamaindex"

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize the LlamaIndex tool wrapper."""
        super().__init__(
            config=config or SecurityConfig(),
            detection_engine=detection_engine,
        )

    def wrap_tools(self, tools: Iterable[Any]) -> list["SecuredLlamaIndexTool"]:
        """Scan and wrap LlamaIndex-compatible tools."""
        return [self.wrap_tool(tool) for tool in tools]

    def wrap_tool(self, tool: Any) -> "SecuredLlamaIndexTool":
        """Scan and wrap one LlamaIndex-compatible tool."""
        tool_name = _tool_name(tool)
        metadata = _tool_metadata(tool)
        decision = self.scan_tool_description(
            tool_name=tool_name,
            description=_tool_description(tool),
            metadata=metadata,
        )
        self._raise_if_blocked(
            decision,
            f"LlamaIndex tool blocked before exposure: {tool_name}",
        )
        return SecuredLlamaIndexTool(tool=tool, wrapper=self)

    def scan_context_chunks(
        self,
        chunks: Iterable[Any],
        config: Optional[dict[str, Any]] = None,
    ) -> list[Any]:
        """Scan retrieved context chunks and return them when allowed."""
        safe_chunks = []
        for chunk in chunks:
            metadata = _context_metadata(chunk)
            decision = self.scan_retrieved_context(
                _context_text(chunk),
                config=config,
                metadata=metadata,
            )
            self._raise_if_blocked(
                decision,
                "LlamaIndex retrieved context blocked",
            )
            safe_chunks.append(chunk)
        return safe_chunks

    def scan_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic LlamaIndex input before execution."""
        return self.scan_tool_arguments("llamaindex_input", payload, config)

    def scan_output(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic LlamaIndex output after execution."""
        return self.scan_tool_output("llamaindex_output", payload, config)

    def _raise_if_blocked(self, decision: Decision, message: str) -> None:
        if decision.action == ThreatAction.BLOCK:
            rules = ", ".join(decision.rule_ids)
            raise BlockedToolError(f"{message} (rules: {rules})")


class SecuredLlamaIndexTool(SecuredRuntimeProxy):
    """Proxy that preserves common LlamaIndex tool invocation methods."""

    def __init__(self, tool: Any, wrapper: ProofLayerToolWrapper) -> None:
        """Create a secured LlamaIndex tool proxy."""
        super().__init__(target=tool, adapter=wrapper)
        self._wrapper = wrapper
        self._tool_name = _tool_name(tool)
        self._metadata = _tool_metadata(tool)

    def call(self, *args: Any, **kwargs: Any) -> Any:
        """Call a LlamaIndex tool with argument and output scanning."""
        config = kwargs.get("config")
        payload = _call_payload(args, kwargs)
        self._scan_arguments(payload, config)
        result = self.target.call(*args, **kwargs)
        self._scan_output(result, config)
        return result

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        """Call a LlamaIndex tool asynchronously with scanning."""
        config = kwargs.get("config")
        payload = _call_payload(args, kwargs)
        self._scan_arguments(payload, config)
        result = await self.target.acall(*args, **kwargs)
        self._scan_output(result, config)
        return result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call a LlamaIndex-compatible tool directly with scanning."""
        config = kwargs.get("config")
        payload = _call_payload(args, kwargs)
        self._scan_arguments(payload, config)
        result = self.target(*args, **kwargs)
        self._scan_output(result, config)
        return result

    def _scan_arguments(
        self,
        payload: Any,
        config: Optional[dict[str, Any]],
    ) -> None:
        decision = self._wrapper.scan_tool_arguments(
            self._tool_name,
            payload,
            config,
            self._metadata,
        )
        self._wrapper._raise_if_blocked(
            decision,
            f"LlamaIndex tool call blocked: {self._tool_name}",
        )

    def _scan_output(
        self,
        output: Any,
        config: Optional[dict[str, Any]],
    ) -> None:
        decision = self._wrapper.scan_tool_output(
            self._tool_name,
            output,
            config,
            self._metadata,
        )
        self._wrapper._raise_if_blocked(
            decision,
            f"LlamaIndex tool output blocked: {self._tool_name}",
        )


def _tool_name(tool: Any) -> str:
    """Return a stable name from LlamaIndex-like tool objects."""
    metadata = getattr(tool, "metadata", None)
    if isinstance(tool, dict):
        return str(tool.get("name") or "unknown_tool")
    return str(
        getattr(metadata, "name", None)
        or getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _tool_description(tool: Any) -> str:
    """Return a searchable description from LlamaIndex-like tool objects."""
    metadata = getattr(tool, "metadata", None)
    if isinstance(tool, dict):
        return str(tool.get("description") or "")
    return str(
        getattr(metadata, "description", None)
        or getattr(tool, "description", None)
        or ""
    )


def _tool_metadata(tool: Any) -> dict[str, Any]:
    """Return audit metadata from LlamaIndex-like tool objects."""
    metadata = getattr(tool, "metadata", None)
    if isinstance(tool, dict):
        return dict(tool.get("metadata") or {})
    if metadata is None:
        return {}
    if isinstance(metadata, dict):
        return dict(metadata)
    return {
        key: value
        for key, value in {
            "name": getattr(metadata, "name", None),
            "description": getattr(metadata, "description", None),
        }.items()
        if value is not None
    }


def _call_payload(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Normalize LlamaIndex tool-call arguments for scanning."""
    payload: dict[str, Any] = {}
    if args:
        payload["args"] = list(args)
    visible_kwargs = {
        key: value
        for key, value in kwargs.items()
        if key not in {"config", "callbacks", "metadata"}
    }
    if visible_kwargs:
        payload["kwargs"] = visible_kwargs
    return payload


def _context_text(chunk: Any) -> Any:
    """Extract searchable text from LlamaIndex context nodes."""
    if isinstance(chunk, str):
        return chunk
    if isinstance(chunk, dict):
        return chunk.get("text") or chunk.get("content") or chunk
    get_content = getattr(chunk, "get_content", None)
    if callable(get_content):
        return get_content()
    return getattr(chunk, "text", None) or getattr(chunk, "content", None) or str(chunk)


def _context_metadata(chunk: Any) -> dict[str, Any]:
    """Extract source metadata from LlamaIndex context nodes."""
    if isinstance(chunk, dict):
        metadata = dict(chunk.get("metadata") or {})
        for key in ("id", "node_id", "source", "doc_id"):
            if key in chunk:
                metadata.setdefault(key, chunk[key])
        return metadata
    metadata = getattr(chunk, "metadata", None)
    if isinstance(metadata, dict):
        result = dict(metadata)
    else:
        result = {}
    for attr in ("id_", "node_id", "source", "doc_id"):
        value = getattr(chunk, attr, None)
        if value is not None:
            result.setdefault(attr, value)
    return result
