"""
Response Actions
================

Handles ALLOW/WARN/BLOCK/KILL actions based on threat detection.
"""

import os
import sys
import signal
import logging
from enum import Enum
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ThreatAction(Enum):
    """Possible actions in response to a detected threat."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    KILL = "KILL"


class ResponseAction:
    """
    Manages response actions for detected threats.
    """

    def __init__(
        self,
        default_action: str = "warn",
        reporter: Optional[Any] = None
    ):
        """
        Initialize response action handler.

        Args:
            default_action: Default action ("allow", "warn", "block", "kill")
            reporter: SecurityReporter instance
        """
        self.default_action = default_action.upper()
        self.reporter = reporter

    def decide_action(self, risk_score: int) -> ThreatAction:
        """
        Decide action based on risk score.

        Args:
            risk_score: Risk score (0-100)

        Returns:
            ThreatAction to take
        """
        if risk_score <= 29:
            return ThreatAction.ALLOW
        elif risk_score <= 69:
            return ThreatAction.WARN
        elif risk_score <= 89:
            return ThreatAction.BLOCK
        else:
            # Score 90-100 = KILL
            if self.default_action == "KILL":
                return ThreatAction.KILL
            else:
                return ThreatAction.BLOCK

    def execute(
        self,
        action: ThreatAction,
        context: Dict[str, Any]
    ) -> None:
        """
        Execute the chosen action.

        Args:
            action: Action to execute
            context: Context information (tool, arguments, risk_score, etc.)
        """
        if action == ThreatAction.ALLOW:
            logger.info(f"ALLOW: {context.get('tool_name')} (score: {context.get('risk_score')})")

        elif action == ThreatAction.WARN:
            logger.warning(
                f"WARN: {context.get('tool_name')} "
                f"(score: {context.get('risk_score')}) - Suspicious activity detected"
            )
            if self.reporter:
                self.reporter.generate_report(
                    threat_type="suspicious_activity",
                    tool_name=context.get("tool_name"),
                    arguments=context.get("arguments", {}),
                    risk_score=context.get("risk_score", 0),
                    matched_rules=context.get("matched_rules", []),
                    action="WARN"
                )

        elif action == ThreatAction.BLOCK:
            logger.error(
                f"BLOCK: {context.get('tool_name')} "
                f"(score: {context.get('risk_score')}) - Threat blocked"
            )
            if self.reporter:
                report = self.reporter.generate_report(
                    threat_type="prompt_injection",
                    tool_name=context.get("tool_name"),
                    arguments=context.get("arguments", {}),
                    risk_score=context.get("risk_score", 0),
                    matched_rules=context.get("matched_rules", []),
                    action="BLOCK"
                )
            raise SecurityViolation(
                f"Tool call blocked: {context.get('tool_name')} "
                f"(risk score: {context.get('risk_score')})"
            )

        elif action == ThreatAction.KILL:
            logger.critical(
                f"KILL: {context.get('tool_name')} "
                f"(score: {context.get('risk_score')}) - Terminating MCP server"
            )
            if self.reporter:
                report = self.reporter.generate_report(
                    threat_type="critical_threat",
                    tool_name=context.get("tool_name"),
                    arguments=context.get("arguments", {}),
                    risk_score=context.get("risk_score", 0),
                    matched_rules=context.get("matched_rules", []),
                    action="SERVER_KILLED"
                )
                logger.critical(f"Security report written: {report['report_path']}")

            self.kill_server(context)

    def kill_server(self, context: Dict[str, Any]) -> None:
        """
        Terminate the MCP server process.

        Args:
            context: Context information for logging
        """
        logger.critical("=" * 80)
        logger.critical("PROOFLAYER RUNTIME SECURITY: CRITICAL THREAT DETECTED")
        logger.critical(f"Tool: {context.get('tool_name')}")
        logger.critical(f"Risk Score: {context.get('risk_score')}")
        logger.critical(f"Action: MCP SERVER TERMINATED")
        logger.critical("=" * 80)

        # Write emergency log
        try:
            with open("/tmp/prooflayer-emergency.log", "a") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"TIMESTAMP: {context.get('timestamp', 'N/A')}\n")
                f.write(f"TOOL: {context.get('tool_name')}\n")
                f.write(f"RISK SCORE: {context.get('risk_score')}\n")
                f.write(f"ARGUMENTS: {context.get('arguments')}\n")
                f.write(f"{'='*80}\n")
        except Exception as e:
            logger.error(f"Failed to write emergency log: {e}")

        # Kill the process
        pid = os.getpid()
        logger.critical(f"Sending SIGTERM to process {pid}")

        # Give a brief moment for logs to flush
        sys.stdout.flush()
        sys.stderr.flush()

        # Terminate
        os.kill(pid, signal.SIGTERM)

        # If still running after 1 second, force kill
        import time
        time.sleep(1)
        os.kill(pid, signal.SIGKILL)


class SecurityViolation(Exception):
    """Raised when a security threat is detected and blocked."""
    pass
