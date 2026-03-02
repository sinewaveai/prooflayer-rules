"""
ProofLayer Middleware
=====================

Reusable scan-and-decide logic shared between the HTTP transport proxy
and the MCP SDK wrapper.
"""

import logging
from typing import Optional, Dict, Any, Tuple

from ..detection.engine import DetectionEngine
from ..detection.models import ScanResult
from ..reporting.reporter import SecurityReporter
from ..response.actions import ResponseAction, ThreatAction

logger = logging.getLogger(__name__)


class ProofLayerMiddleware:
    """
    Encapsulates the core scan → decide → report pipeline.

    Used by both ProofLayerTransportProxy and ProofLayerMCPWrapper
    to share security scanning logic.
    """

    def __init__(
        self,
        engine: DetectionEngine,
        reporter: SecurityReporter,
        response_action: ResponseAction,
    ):
        self.engine = engine
        self.reporter = reporter
        self.response_action = response_action

    def check_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Tuple[ScanResult, ThreatAction, Optional[Dict[str, Any]]]:
        """
        Scan a tool call and decide on an action.

        Args:
            tool_name: MCP tool name.
            arguments: Tool call arguments.

        Returns:
            (scan_result, action, report_or_None)
        """
        result = self.engine.scan(tool_name=tool_name, arguments=arguments)
        action = self.response_action.decide_action(result.score)

        report = None
        if action in (ThreatAction.BLOCK, ThreatAction.KILL):
            threat_type = "unknown"
            if result.matched_rules:
                top_rule = max(result.matched_rules, key=lambda r: r.score)
                threat_type = top_rule.category

            report = self.reporter.generate_report(
                threat_type=threat_type,
                tool_name=tool_name,
                arguments=arguments,
                risk_score=result.score,
                matched_rules=result.matched_rules,
                action=action.value,
                scan_result=result,
            )

            logger.warning(
                "BLOCKED tool call: %s (score=%d, action=%s, rules=%s)",
                tool_name, result.score, action.value,
                [r.id for r in result.matched_rules],
            )

        elif action == ThreatAction.WARN:
            logger.warning(
                "SUSPICIOUS tool call: %s (score=%d, rules=%s)",
                tool_name, result.score,
                [r.id for r in result.matched_rules],
            )

        return result, action, report
