"""
ProofLayer Runtime Wrapper
===========================

Wraps MCP servers with runtime security monitoring.
"""

import os
import sys
import json
import logging
from typing import Any, Dict, Optional, Callable
from pathlib import Path

from ..detection.engine import DetectionEngine
from ..response.actions import ResponseAction, ThreatAction
from ..reporting.reporter import SecurityReporter
from ..config.loader import ConfigLoader


logger = logging.getLogger(__name__)


class ProofLayerRuntime:
    """
    Runtime security wrapper for MCP servers.

    Usage:
        runtime = ProofLayerRuntime(config_path="prooflayer.yaml")
        protected_server = runtime.wrap(mcp_server)
        protected_server.run()
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        detection_rules: Optional[str] = None,
        action_on_threat: str = "kill",
        report_dir: Optional[str] = None,
        score_threshold: Optional[Dict[str, tuple]] = None
    ):
        """
        Initialize ProofLayer Runtime.

        Args:
            config_path: Path to YAML config file
            detection_rules: Rules to load ("prompt-injection", "all")
            action_on_threat: Action on threat detection ("allow", "warn", "block", "kill")
            report_dir: Directory for security reports
            score_threshold: Dict with allow/warn/block ranges
        """
        self.config = self._load_config(config_path)

        # Override config with explicit parameters
        if detection_rules:
            self.config["detection"]["rules"] = detection_rules
        if action_on_threat:
            self.config["response"]["on_threat"] = action_on_threat
        if report_dir:
            self.config["response"]["report_dir"] = report_dir
        if score_threshold:
            self.config["detection"]["score_threshold"] = score_threshold

        # Initialize components
        self.detection_engine = DetectionEngine(
            rules_dir=self.config["detection"].get("rules_dir"),
            score_threshold=self.config["detection"].get("score_threshold")
        )

        self.reporter = SecurityReporter(
            report_dir=self.config["response"].get("report_dir", "./security-reports")
        )

        self.response_action = ResponseAction(
            default_action=self.config["response"].get("on_threat", "warn"),
            reporter=self.reporter
        )

        logger.info(f"ProofLayer Runtime v0.1.0 initialized")
        logger.info(f"Detection rules loaded: {len(self.detection_engine.rules)}")
        logger.info(f"Default action on threat: {self.response_action.default_action}")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        if config_path and os.path.exists(config_path):
            return ConfigLoader.load(config_path)

        # Default configuration
        return {
            "detection": {
                "enabled": True,
                "rules_dir": None,  # Will use packaged rules
                "score_threshold": {
                    "allow": (0, 29),
                    "warn": (30, 69),
                    "block": (70, 100)
                }
            },
            "response": {
                "on_threat": "warn",  # Conservative default
                "report_dir": "./security-reports",
                "alert_webhook": None
            },
            "performance": {
                "max_latency_ms": 10,
                "cache_rules": True
            },
            "logging": {
                "level": "INFO",
                "format": "json"
            }
        }

    def wrap(self, mcp_server: Any) -> "ProtectedMCPServer":
        """
        Wrap an MCP server with ProofLayer security.

        Args:
            mcp_server: Original MCP server instance

        Returns:
            Protected MCP server with runtime security
        """
        return ProtectedMCPServer(
            mcp_server=mcp_server,
            detection_engine=self.detection_engine,
            response_action=self.response_action,
            reporter=self.reporter
        )

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[int, ThreatAction, Dict[str, Any]]:
        """
        Scan a single MCP tool call for threats.

        Args:
            tool_name: Name of the MCP tool
            arguments: Tool call arguments
            context: Additional context (message ID, timestamp, etc.)

        Returns:
            Tuple of (risk_score, action, detection_details)
        """
        # Run detection
        risk_score, matched_rules = self.detection_engine.scan(
            tool_name=tool_name,
            arguments=arguments
        )

        # Determine action based on score
        if risk_score <= self.config["detection"]["score_threshold"]["allow"][1]:
            action = ThreatAction.ALLOW
        elif risk_score <= self.config["detection"]["score_threshold"]["warn"][1]:
            action = ThreatAction.WARN
        else:
            action = ThreatAction.BLOCK

        detection_details = {
            "risk_score": risk_score,
            "matched_rules": [rule.id for rule in matched_rules],
            "confidence": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 30 else "LOW"
        }

        return risk_score, action, detection_details


class ProtectedMCPServer:
    """
    MCP server wrapped with ProofLayer runtime security.
    """

    def __init__(
        self,
        mcp_server: Any,
        detection_engine: DetectionEngine,
        response_action: ResponseAction,
        reporter: SecurityReporter
    ):
        self.mcp_server = mcp_server
        self.detection_engine = detection_engine
        self.response_action = response_action
        self.reporter = reporter

        # Wrap the original tool call handler
        self._wrap_tool_handlers()

    def _wrap_tool_handlers(self):
        """Intercept MCP tool calls and inject security scanning."""
        original_call_tool = getattr(self.mcp_server, "call_tool", None)

        if original_call_tool:
            def wrapped_call_tool(tool_name: str, arguments: Dict[str, Any]):
                # Security scan before execution
                risk_score, matched_rules = self.detection_engine.scan(
                    tool_name=tool_name,
                    arguments=arguments
                )

                # Determine action
                action = self.response_action.decide_action(risk_score)

                if action == ThreatAction.BLOCK or action == ThreatAction.KILL:
                    # Generate security report
                    report = self.reporter.generate_report(
                        threat_type="prompt_injection",
                        tool_name=tool_name,
                        arguments=arguments,
                        risk_score=risk_score,
                        matched_rules=matched_rules,
                        action=action.value
                    )

                    logger.error(f"THREAT DETECTED: {tool_name} - Score: {risk_score} - Action: {action.value}")

                    if action == ThreatAction.KILL:
                        # Kill the MCP server
                        self.response_action.kill_server(report)

                    raise SecurityError(f"Tool call blocked: {tool_name} (risk score: {risk_score})")

                elif action == ThreatAction.WARN:
                    logger.warning(f"SUSPICIOUS: {tool_name} - Score: {risk_score}")

                # Allow the call to proceed
                return original_call_tool(tool_name, arguments)

            # Replace the original method
            setattr(self.mcp_server, "call_tool", wrapped_call_tool)

    def run(self):
        """Run the protected MCP server."""
        logger.info("Starting ProofLayer-protected MCP server")
        return self.mcp_server.run()


class SecurityError(Exception):
    """Raised when a security threat is detected."""
    pass
