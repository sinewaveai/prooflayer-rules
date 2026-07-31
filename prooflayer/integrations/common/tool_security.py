"""Reusable tool security scanner for runtime integrations."""

from datetime import datetime, timezone
from typing import Any, Optional

from ...detection.engine import DetectionEngine
from ...detection.models import DetectionRule, ScanResult
from ...response.actions import ThreatAction
from .audit import AuditEventRecorder
from .config import RuntimeSecurityConfig
from .decisions import Decision
from .envelope import extract_config_session_id

_TOOL_POISONING_RULE_CATEGORIES = {
    "tool_poisoning",
    "direct_injection",
    "jailbreak",
    "role_manipulation",
}
_TOOL_ARGUMENT_RULE_CATEGORIES = {
    "command_injection",
    "sql_injection",
    "ssrf_xxe",
    "direct_injection",
    "jailbreak",
    "role_manipulation",
}
_ARGUMENT_EXFIL_RULE_CATEGORIES = {"data_exfiltration"}
_TOOL_OUTPUT_RULE_CATEGORIES = {
    "data_exfiltration",
    "direct_injection",
    "tool_poisoning",
}
_CONTEXT_RULE_CATEGORIES = {
    "direct_injection",
    "jailbreak",
    "role_manipulation",
    "data_exfiltration",
    "tool_poisoning",
}


class RuntimeToolSecurity:
    """Shared scanner for integration tool metadata, arguments, and outputs."""

    integration_name = "runtime"

    def __init__(
        self,
        config: Optional[RuntimeSecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize runtime tool security with config and detection rules."""
        self.config = config or RuntimeSecurityConfig()
        self.detection_engine = detection_engine or DetectionEngine()
        self._audit_recorder = AuditEventRecorder()

    def get_audit_log(self, session_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Return audit events, optionally filtered by session ID."""
        return self._audit_recorder.list(session_id)

    def record_event(self, event: dict[str, Any]) -> None:
        """Record an audit event with chain-of-custody hashing."""
        self._audit_recorder.append(event)

    def extract_session_id(
        self,
        config: Optional[dict[str, Any]] = None,
        payload: Any = None,
    ) -> Optional[str]:
        """Extract a session ID from runtime config or payload."""
        return extract_config_session_id(self.config.session_id_key, config, payload)

    def scan_tool_description(
        self,
        tool_name: str,
        description: str,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan tool metadata before a tool is exposed to an agent."""
        return self._scan_rule_categories(
            category="tool_poisoning",
            rule_categories=_TOOL_POISONING_RULE_CATEGORIES,
            configured_action=self.config.tool_poisoning,
            tool_name=tool_name,
            payload={"name": tool_name, "description": description},
            config=config,
            metadata=metadata,
        )

    def scan_tool_arguments(
        self,
        tool_name: str,
        arguments: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan tool arguments before execution."""
        policy_decision = self._scan_tool_policy(tool_name, arguments, config, metadata)
        if policy_decision.action != ThreatAction.ALLOW:
            return policy_decision
        exfil_decision = self._scan_rule_categories(
            category="tool_arguments",
            rule_categories=_ARGUMENT_EXFIL_RULE_CATEGORIES,
            configured_action=self.config.exfil,
            tool_name=tool_name,
            payload=arguments,
            config=config,
            metadata=metadata,
        )
        if exfil_decision.action == ThreatAction.BLOCK:
            return exfil_decision
        abuse_decision = self._scan_rule_categories(
            category="tool_arguments",
            rule_categories=_TOOL_ARGUMENT_RULE_CATEGORIES,
            configured_action=self.config.tool_abuse,
            tool_name=tool_name,
            payload=arguments,
            config=config,
            metadata=metadata,
        )
        if abuse_decision.action != ThreatAction.ALLOW:
            return abuse_decision
        return exfil_decision

    def scan_tool_output(
        self,
        tool_name: str,
        output: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan tool output before returning it to an agent."""
        return self._scan_rule_categories(
            category="tool_output",
            rule_categories=_TOOL_OUTPUT_RULE_CATEGORIES,
            configured_action=self.config.exfil,
            tool_name=tool_name,
            payload=output,
            config=config,
            metadata=metadata,
        )

    def scan_retrieved_context(
        self,
        context: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan retrieved context before it is added to an agent prompt."""
        tool_name = "retrieved_context"
        return self._scan_rule_categories(
            category="retrieved_context",
            rule_categories=_CONTEXT_RULE_CATEGORIES,
            configured_action=self.config.prompt_injection,
            tool_name=tool_name,
            payload=context,
            config=config,
            metadata=metadata,
        )

    def _scan_tool_policy(
        self,
        tool_name: str,
        arguments: Any,
        config: Optional[dict[str, Any]],
        metadata: Optional[dict[str, Any]],
    ) -> Decision:
        blocked_tools = set(self.config.blocked_tools or [])
        allowed_tools = set(self.config.allowed_tools or [])
        if tool_name in blocked_tools:
            return self._record_policy_event(
                rule_id="prooflayer-tool-blocked",
                reason=f"Tool {tool_name!r} is explicitly blocked",
                tool_name=tool_name,
                arguments=arguments,
                config=config,
                metadata=metadata,
            )
        if allowed_tools and tool_name not in allowed_tools:
            return self._record_policy_event(
                rule_id="prooflayer-tool-not-allowed",
                reason=f"Tool {tool_name!r} is not in the allowlist",
                tool_name=tool_name,
                arguments=arguments,
                config=config,
                metadata=metadata,
            )
        return Decision.allow()

    def _record_policy_event(
        self,
        rule_id: str,
        reason: str,
        tool_name: str,
        arguments: Any,
        config: Optional[dict[str, Any]],
        metadata: Optional[dict[str, Any]],
    ) -> Decision:
        action = ThreatAction(self.config.tool_abuse.upper())
        event_metadata = dict(metadata or {})
        self.record_event(
            {
                "event_type": "detection",
                "integration": self.integration_name,
                "category": "tool_policy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.extract_session_id(config, arguments),
                "decision": action.value,
                "risk_score": 100,
                "tool_name": tool_name,
                "arguments": arguments,
                "metadata": event_metadata,
                "rule_ids": [rule_id],
                "rule_sources": [
                    {
                        "id": rule_id,
                        "category": "tool_policy",
                        "severity": "critical",
                        "message": reason,
                        "source": "prooflayer",
                    }
                ],
            }
        )
        return Decision(
            action=action,
            category="tool_policy",
            risk_score=100,
            rule_ids=[rule_id],
            reason=reason,
            metadata=event_metadata,
        )

    def _scan_rule_categories(
        self,
        category: str,
        rule_categories: set[str],
        configured_action: str,
        tool_name: str,
        payload: Any,
        config: Optional[dict[str, Any]],
        metadata: Optional[dict[str, Any]],
    ) -> Decision:
        scan_result = self.detection_engine.scan(
            tool_name=tool_name,
            arguments={"payload": payload, "metadata": metadata or {}},
        )
        matched_rules = [
            rule
            for rule in scan_result.matched_rules
            if rule.category in rule_categories
        ]
        if not matched_rules:
            return Decision.allow()

        action = ThreatAction(configured_action.upper())
        self._record_detection_event(
            category=category,
            tool_name=tool_name,
            payload=payload,
            config=config,
            metadata=metadata,
            action=action,
            scan_result=scan_result,
            matched_rules=matched_rules,
        )
        return Decision(
            action=action,
            category=category,
            risk_score=scan_result.score,
            rule_ids=[rule.id for rule in matched_rules],
            reason=", ".join(rule.message for rule in matched_rules),
            metadata=dict(metadata or {}),
        )

    def _record_detection_event(
        self,
        category: str,
        tool_name: str,
        payload: Any,
        config: Optional[dict[str, Any]],
        metadata: Optional[dict[str, Any]],
        action: ThreatAction,
        scan_result: ScanResult,
        matched_rules: list[DetectionRule],
    ) -> None:
        self.record_event(
            {
                "event_type": "detection",
                "integration": self.integration_name,
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.extract_session_id(config, payload),
                "decision": action.value,
                "risk_score": scan_result.score,
                "latency_ms": scan_result.latency_ms,
                "tool_name": tool_name,
                "payload": payload,
                "metadata": dict(metadata or {}),
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
