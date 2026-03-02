"""
ProofLayer MCP SDK Wrapper
===========================

Async-compatible wrapper that integrates with the real MCP Python SDK.
Intercepts tool calls and tool listings for security scanning.

Usage:
    from prooflayer.runtime.mcp_wrapper import ProofLayerMCPWrapper

    wrapper = ProofLayerMCPWrapper(config=config)
    protected_server = wrapper.wrap(mcp_server)

Requires: pip install prooflayer-runtime[mcp]
"""

import logging
import functools
from typing import Any, Dict, List, Optional, Sequence

from ..detection.engine import DetectionEngine
from ..detection.rules import RuleLoadError
from ..response.actions import ResponseAction, ThreatAction
from ..reporting.reporter import SecurityReporter
from ..config.loader import ConfigLoader

logger = logging.getLogger(__name__)

# Lazy import for MCP SDK — it's an optional dependency
_mcp_available = None


def _check_mcp_available():
    """Check if the MCP SDK is installed, caching the result."""
    global _mcp_available
    if _mcp_available is None:
        try:
            import mcp  # noqa: F401
            _mcp_available = True
        except ImportError:
            _mcp_available = False
    return _mcp_available


class MCPDependencyError(ImportError):
    """Raised when the MCP SDK is required but not installed."""
    pass


class ProofLayerMCPWrapper:
    """
    Async-compatible security wrapper for MCP Python SDK servers.

    Intercepts:
    - call_tool: scans tool call arguments before execution, scans outputs after
    - list_tools: scans tool descriptions for prompt injection (tool poisoning)
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        detection_rules_dir: Optional[str] = None,
        action_on_threat: str = "block",
        report_dir: Optional[str] = None,
        scan_tool_descriptions: bool = True,
        scan_tool_outputs: bool = True,
        fail_closed: bool = True,
    ):
        """
        Initialize the MCP wrapper.

        Args:
            config: Configuration dict (takes precedence over config_path)
            config_path: Path to YAML config file
            detection_rules_dir: Directory containing YAML rule files
            action_on_threat: Action on threat detection ("allow", "warn", "block", "kill")
            report_dir: Directory for security reports
            scan_tool_descriptions: Scan tool descriptions for prompt injection
            scan_tool_outputs: Scan tool outputs before returning to LLM
            fail_closed: Block all requests if rules fail to load (default True)
        """
        if not _check_mcp_available():
            raise MCPDependencyError(
                "The 'mcp' package is required for MCP SDK integration. "
                "Install it with: pip install prooflayer-runtime[mcp]"
            )

        # Build config from file or dict, with parameter overrides
        if config:
            self.config = config
        elif config_path:
            self.config = ConfigLoader.load(config_path)
        else:
            self.config = self._default_config()

        # Apply parameter overrides
        detection_cfg = self.config.setdefault("detection", {})
        response_cfg = self.config.setdefault("response", {})

        if detection_rules_dir:
            detection_cfg["rules_dir"] = detection_rules_dir
        if action_on_threat:
            response_cfg["on_threat"] = action_on_threat
        if report_dir:
            response_cfg["report_dir"] = report_dir

        detection_cfg["fail_closed"] = fail_closed

        self.scan_tool_descriptions = scan_tool_descriptions
        self.scan_tool_outputs = scan_tool_outputs

        # Initialize detection engine
        self.detection_engine = DetectionEngine(
            rules_dir=detection_cfg.get("rules_dir"),
            score_threshold=detection_cfg.get("score_threshold"),
            fail_closed=fail_closed,
        )

        self.reporter = SecurityReporter(
            report_dir=response_cfg.get("report_dir", "./security-reports")
        )

        self.response_action = ResponseAction(
            default_action=response_cfg.get("on_threat", "block"),
            reporter=self.reporter,
        )

        logger.info(
            "ProofLayer MCP wrapper initialized with %d rules",
            len(self.detection_engine.rules),
        )

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        return {
            "detection": {
                "enabled": True,
                "rules_dir": None,
                "fail_closed": True,
                "score_threshold": {
                    "allow": (0, 29),
                    "warn": (30, 69),
                    "block": (70, 100),
                },
            },
            "response": {
                "on_threat": "block",
                "report_dir": "./security-reports",
                "alert_webhook": None,
            },
        }

    def wrap(self, server: Any) -> Any:
        """
        Wrap an MCP Server instance with ProofLayer security scanning.

        This hooks into the server's call_tool and list_tools handlers
        by registering wrapped handlers that scan inputs/outputs.

        Args:
            server: An mcp.server.Server (or mcp.server.fastmcp.FastMCP) instance

        Returns:
            The same server instance, with security hooks installed
        """
        from mcp.server import Server as MCPServer

        if not isinstance(server, MCPServer):
            # FastMCP or other wrappers might have a ._mcp_server attribute
            inner = getattr(server, "_mcp_server", None)
            if inner is not None and isinstance(inner, MCPServer):
                self._install_hooks(inner)
            else:
                # Attempt to install hooks directly — duck typing
                self._install_hooks(server)
        else:
            self._install_hooks(server)

        logger.info("ProofLayer security hooks installed on MCP server")
        return server

    def _install_hooks(self, server: Any) -> None:
        """Install call_tool and list_tools security hooks on the server."""
        self._wrap_call_tool(server)
        if self.scan_tool_descriptions:
            self._wrap_list_tools(server)

    def _wrap_call_tool(self, server: Any) -> None:
        """
        Wrap the server's call_tool handler to scan inputs and outputs.

        The MCP SDK uses @server.call_tool() as a decorator that registers
        a handler. We intercept the registration to wrap the handler.
        """
        original_call_tool_decorator = getattr(server, "call_tool", None)
        if original_call_tool_decorator is None:
            logger.warning(
                "MCP server has no call_tool method; cannot install input scanning"
            )
            return

        wrapper_self = self

        def secured_call_tool_decorator():
            """Replacement decorator that wraps the user's handler with security."""

            def decorator(handler):
                @functools.wraps(handler)
                async def secured_handler(name: str, arguments: Optional[Dict[str, Any]] = None):
                    arguments = arguments or {}

                    # --- Input scanning ---
                    risk_score, matched_rules = wrapper_self.detection_engine.scan(
                        tool_name=name,
                        arguments=arguments,
                    )

                    action = wrapper_self.response_action.decide_action(risk_score)

                    if action in (ThreatAction.BLOCK, ThreatAction.KILL):
                        wrapper_self.reporter.generate_report(
                            threat_type="prompt_injection",
                            tool_name=name,
                            arguments=arguments,
                            risk_score=risk_score,
                            matched_rules=matched_rules,
                            action=action.value,
                        )
                        logger.error(
                            "BLOCKED tool call: %s (score=%d, action=%s, rules=%s)",
                            name,
                            risk_score,
                            action.value,
                            [r.id for r in matched_rules],
                        )

                        from mcp.types import TextContent, CallToolResult

                        return CallToolResult(
                            content=[
                                TextContent(
                                    type="text",
                                    text=f"Tool call blocked by ProofLayer: {name} "
                                    f"(risk score: {risk_score})",
                                )
                            ],
                            isError=True,
                        )

                    if action == ThreatAction.WARN:
                        logger.warning(
                            "SUSPICIOUS tool call: %s (score=%d, rules=%s)",
                            name,
                            risk_score,
                            [r.id for r in matched_rules],
                        )

                    # --- Execute the original handler ---
                    result = await handler(name, arguments)

                    # --- Output scanning ---
                    if wrapper_self.scan_tool_outputs and result is not None:
                        result = await wrapper_self._scan_tool_output(name, result)

                    return result

                # Register the secured handler using the original decorator
                return original_call_tool_decorator()(secured_handler)

            return decorator

        server.call_tool = secured_call_tool_decorator

    def _wrap_list_tools(self, server: Any) -> None:
        """
        Wrap the server's list_tools handler to scan tool descriptions
        for prompt injection (tool poisoning attacks).
        """
        original_list_tools_decorator = getattr(server, "list_tools", None)
        if original_list_tools_decorator is None:
            logger.warning(
                "MCP server has no list_tools method; cannot install description scanning"
            )
            return

        wrapper_self = self

        def secured_list_tools_decorator():
            """Replacement decorator that scans tool descriptions."""

            def decorator(handler):
                @functools.wraps(handler)
                async def secured_handler():
                    result = await handler()

                    # Scan each tool's description for prompt injection
                    if result is not None:
                        tools = result if isinstance(result, list) else getattr(result, "tools", [])
                        for tool in tools:
                            desc = getattr(tool, "description", None) or ""
                            if not desc:
                                continue

                            score, matched = wrapper_self.detection_engine.scan(
                                tool_name=getattr(tool, "name", "unknown"),
                                arguments={"description": desc},
                            )

                            if score >= 30:
                                tool_name = getattr(tool, "name", "unknown")
                                logger.warning(
                                    "TOOL POISONING detected in '%s' description "
                                    "(score=%d, rules=%s)",
                                    tool_name,
                                    score,
                                    [r.id for r in matched],
                                )
                                wrapper_self.reporter.generate_report(
                                    threat_type="tool_poisoning",
                                    tool_name=tool_name,
                                    arguments={"description": desc},
                                    risk_score=score,
                                    matched_rules=matched,
                                    action="WARN",
                                )

                    return result

                return original_list_tools_decorator()(secured_handler)

            return decorator

        server.list_tools = secured_list_tools_decorator

    async def _scan_tool_output(self, tool_name: str, result: Any) -> Any:
        """
        Scan tool output for threats before it is returned to the LLM.

        Checks for data exfiltration payloads, injected instructions, etc.
        in the tool's response content.
        """
        from mcp.types import CallToolResult, TextContent

        if not isinstance(result, CallToolResult):
            return result

        for content_item in result.content:
            if not isinstance(content_item, TextContent):
                continue

            text = content_item.text or ""
            if not text:
                continue

            score, matched = self.detection_engine.scan(
                tool_name=f"{tool_name}:output",
                arguments={"response_text": text},
            )

            if score >= 70:
                logger.error(
                    "BLOCKED tool output from '%s' (score=%d, rules=%s)",
                    tool_name,
                    score,
                    [r.id for r in matched],
                )
                self.reporter.generate_report(
                    threat_type="malicious_output",
                    tool_name=tool_name,
                    arguments={"response_text": text[:500]},
                    risk_score=score,
                    matched_rules=matched,
                    action="BLOCK",
                )
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=f"Tool output blocked by ProofLayer: {tool_name} "
                            f"output contained suspicious content (risk score: {score})",
                        )
                    ],
                    isError=True,
                )

            if score >= 30:
                logger.warning(
                    "SUSPICIOUS tool output from '%s' (score=%d, rules=%s)",
                    tool_name,
                    score,
                    [r.id for r in matched],
                )

        return result
