"""Tool call validation for ProofLayer-protected LangGraph agents."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ...detection.models import DetectionRule
from ...response.actions import ThreatAction
from .exceptions import BlockedError

if TYPE_CHECKING:
    from .middleware import SecurityMiddleware


_TOOL_ARGUMENT_RULE_CATEGORIES = {
    "command_injection",
    "data_exfiltration",
    "ssrf_xxe",
    "sql_injection",
    "tool_poisoning",
}


class ToolValidator:
    """Validate LangGraph tool calls before execution."""

    def __init__(self, middleware: "SecurityMiddleware") -> None:
        """Create a validator bound to a middleware instance."""
        self.middleware = middleware

    def validate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Validate a tool call against allowlists and argument rules."""
        allowlist_action = self._validate_allowlist(tool_name, arguments, config)
        if allowlist_action != ThreatAction.ALLOW:
            return allowlist_action
        return self._validate_arguments(tool_name, arguments, config)

    def capture_output(
        self,
        tool_name: str,
        output: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record tool output for later audit and output-inspection hooks."""
        self.middleware.record_event(
            {
                "event_type": "tool_output",
                "tool_name": tool_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.middleware.extract_session_id(config, output),
                "output": output,
            }
        )

    def _validate_allowlist(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        allowed_tools = self.middleware.config.allowed_tools
        if allowed_tools is None or tool_name in allowed_tools:
            return ThreatAction.ALLOW

        action = ThreatAction(self.middleware.config.tool_abuse.upper())
        self._record_synthetic_event(
            category="tool_abuse",
            rule_id="tool-allowlist-deny",
            severity="high",
            message=f"Tool {tool_name!r} is not in the configured allowlist",
            tool_name=tool_name,
            arguments=arguments,
            config=config,
            action=action,
            risk_score=75,
        )
        if action == ThreatAction.BLOCK:
            raise BlockedError(f"LangGraph tool call blocked: {tool_name}")
        return action

    def _validate_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        scan_result = self.middleware.detection_engine.scan(tool_name, arguments)
        matched_rules = [
            rule
            for rule in scan_result.matched_rules
            if rule.category in _TOOL_ARGUMENT_RULE_CATEGORIES
        ]
        if not matched_rules:
            return ThreatAction.ALLOW

        action = ThreatAction(self.middleware.config.exfil.upper())
        self._record_rule_event(
            category="tool_arguments",
            tool_name=tool_name,
            arguments=arguments,
            config=config,
            action=action,
            risk_score=scan_result.score,
            latency_ms=scan_result.latency_ms,
            matched_rules=matched_rules,
        )
        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(rule.id for rule in matched_rules)
            raise BlockedError(
                f"LangGraph tool call blocked: suspicious arguments ({rule_ids})"
            )
        return action

    def _record_synthetic_event(
        self,
        category: str,
        rule_id: str,
        severity: str,
        message: str,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]],
        action: ThreatAction,
        risk_score: int,
    ) -> None:
        self.middleware.record_event(
            {
                "event_type": "detection",
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.middleware.extract_session_id(config, arguments),
                "decision": action.value,
                "risk_score": risk_score,
                "tool_name": tool_name,
                "arguments": arguments,
                "rule_ids": [rule_id],
                "rule_sources": [
                    {
                        "id": rule_id,
                        "category": category,
                        "severity": severity,
                        "message": message,
                        "source": "prooflayer-langgraph",
                    }
                ],
            }
        )

    def _record_rule_event(
        self,
        category: str,
        tool_name: str,
        arguments: Dict[str, Any],
        config: Optional[Dict[str, Any]],
        action: ThreatAction,
        risk_score: int,
        latency_ms: float,
        matched_rules: List[DetectionRule],
    ) -> None:
        self.middleware.record_event(
            {
                "event_type": "detection",
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.middleware.extract_session_id(config, arguments),
                "decision": action.value,
                "risk_score": risk_score,
                "latency_ms": latency_ms,
                "tool_name": tool_name,
                "arguments": arguments,
                "rule_ids": [rule.id for rule in matched_rules],
                "rule_sources": [
                    {
                        "id": rule.id,
                        "category": rule.category,
                        "severity": rule.severity,
                        "message": rule.message,
                    }
                    for rule in matched_rules
                ],
            }
        )
