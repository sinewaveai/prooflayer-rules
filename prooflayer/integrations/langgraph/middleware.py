"""Security middleware for LangGraph compiled graphs."""

from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ...detection.engine import DetectionEngine
from ...detection.models import DetectionRule, ScanResult
from ...detection.multi_turn import MultiTurnDetector
from ...detection.scope_drift import ScopeDriftDetector, ScopeDriftFinding
from ...detection.state_manipulation import StateManipulationDetector
from ...response.actions import ThreatAction
from .config import SecurityConfig
from .exceptions import BlockedError
from .hooks import HookAdapter
from .tool_validator import ToolValidator


_PROMPT_INJECTION_RULE_CATEGORIES = {"direct_injection"}
_OUTPUT_EXFIL_RULE_CATEGORIES = {"data_exfiltration"}


class SecurityMiddleware:
    """Wrap a compiled LangGraph with ProofLayer runtime security checks."""

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ) -> None:
        """Initialize middleware with a validated security configuration."""
        self.config = config or SecurityConfig()
        self.detection_engine = detection_engine or DetectionEngine()
        self.scope_drift_detector = ScopeDriftDetector()
        self.state_manipulation_detector = StateManipulationDetector()
        self.multi_turn_detector = MultiTurnDetector()
        self._audit_log: List[Dict[str, Any]] = []
        self.hooks = HookAdapter(self)
        self.tool_validator = ToolValidator(self)

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

    def scan_input(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Scan graph input before execution.

        Prompt injection detection is active on the node-entry hot path.
        """
        prompt_action = self._scan_prompt_injection(payload, config)
        if prompt_action == ThreatAction.BLOCK:
            return prompt_action
        multi_turn_action = self._scan_multi_turn(payload, config)
        if multi_turn_action != ThreatAction.ALLOW:
            return multi_turn_action
        return prompt_action

    def scan_output(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Scan graph output after execution.

        Output inspection detects data exfiltration and scope drift signals.
        """
        exfil_action = self._scan_output_exfiltration(payload, config)
        if exfil_action == ThreatAction.BLOCK:
            return exfil_action
        scope_action = self._scan_scope_drift(payload, config)
        if scope_action != ThreatAction.ALLOW:
            return scope_action
        return exfil_action

    def scan_state_update(
        self,
        state_update: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> ThreatAction:
        """Scan LangGraph state updates for memory or prompt manipulation."""
        findings = self.state_manipulation_detector.detect(state_update)
        if not findings:
            return ThreatAction.ALLOW

        action = ThreatAction(self.config.state_manipulation.upper())
        self._record_finding_event(
            category="state_manipulation",
            payload=state_update,
            config=config,
            action=action,
            findings=findings,
        )
        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(finding.rule_id for finding in findings)
            raise BlockedError(
                "LangGraph execution blocked: state manipulation detected "
                f"(rules: {rule_ids})"
            )
        return action

    def _scan_prompt_injection(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        scan_result = self.detection_engine.scan(
            tool_name="langgraph_input",
            arguments={"payload": payload},
        )
        matched_rules = [
            rule
            for rule in scan_result.matched_rules
            if rule.category in _PROMPT_INJECTION_RULE_CATEGORIES
        ]
        if not matched_rules:
            return ThreatAction.ALLOW

        configured_action = self.config.prompt_injection
        action = ThreatAction(configured_action.upper())
        self._record_detection_event(
            category="prompt_injection",
            payload=payload,
            config=config,
            action=action,
            scan_result=scan_result,
            matched_rules=matched_rules,
        )

        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(rule.id for rule in matched_rules)
            raise BlockedError(
                "LangGraph execution blocked: prompt injection detected "
                f"(rules: {rule_ids})"
            )

        return action

    def _record_detection_event(
        self,
        category: str,
        payload: Any,
        config: Optional[Dict[str, Any]],
        action: ThreatAction,
        scan_result: ScanResult,
        matched_rules: List[DetectionRule],
    ) -> None:
        self.record_event(
            {
                "event_type": "detection",
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.extract_session_id(config, payload),
                "decision": action.value,
                "risk_score": scan_result.score,
                "latency_ms": scan_result.latency_ms,
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
                "payload": payload,
            }
        )

    def _scan_output_exfiltration(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        scan_result = self.detection_engine.scan(
            tool_name="langgraph_output",
            arguments={"payload": payload},
        )
        matched_rules = [
            rule
            for rule in scan_result.matched_rules
            if rule.category in _OUTPUT_EXFIL_RULE_CATEGORIES
        ]
        if not matched_rules:
            return ThreatAction.ALLOW

        action = ThreatAction(self.config.exfil.upper())
        self._record_detection_event(
            category="exfil",
            payload=payload,
            config=config,
            action=action,
            scan_result=scan_result,
            matched_rules=matched_rules,
        )
        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(rule.id for rule in matched_rules)
            raise BlockedError(
                "LangGraph execution blocked: output exfiltration detected "
                f"(rules: {rule_ids})"
            )
        return action

    def _scan_scope_drift(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        findings = self.scope_drift_detector.detect(payload)
        if not findings:
            return ThreatAction.ALLOW

        action = ThreatAction(self.config.scope_drift.upper())
        self._record_finding_event(
            category="scope_drift",
            payload=payload,
            config=config,
            action=action,
            findings=findings,
        )
        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(finding.rule_id for finding in findings)
            raise BlockedError(
                "LangGraph execution blocked: scope drift detected "
                f"(rules: {rule_ids})"
            )
        return action

    def _scan_multi_turn(
        self,
        payload: Any,
        config: Optional[Dict[str, Any]],
    ) -> ThreatAction:
        session_id = self.extract_session_id(config, payload) or "__default__"
        findings = self.multi_turn_detector.detect(session_id, payload)
        if not findings:
            return ThreatAction.ALLOW

        action = ThreatAction(self.config.multi_turn.upper())
        self._record_finding_event(
            category="multi_turn",
            payload=payload,
            config=config,
            action=action,
            findings=findings,
        )
        if action == ThreatAction.BLOCK:
            rule_ids = ", ".join(finding.rule_id for finding in findings)
            raise BlockedError(
                "LangGraph execution blocked: multi-turn attack detected "
                f"(rules: {rule_ids})"
            )
        return action

    def _record_finding_event(
        self,
        category: str,
        payload: Any,
        config: Optional[Dict[str, Any]],
        action: ThreatAction,
        findings: List[Any],
    ) -> None:
        self.record_event(
            {
                "event_type": "detection",
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.extract_session_id(config, payload),
                "decision": action.value,
                "risk_score": min(sum(finding.score for finding in findings), 100),
                "rule_ids": [finding.rule_id for finding in findings],
                "rule_sources": [
                    {
                        "id": finding.rule_id,
                        "category": category,
                        "severity": finding.severity,
                        "message": finding.message,
                        "source": "prooflayer-langgraph",
                    }
                    for finding in findings
                ],
                "payload": payload,
            }
        )


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
