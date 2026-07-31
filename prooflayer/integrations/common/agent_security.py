"""Shared agent-runtime security helpers for ProofLayer integrations."""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Optional, TypeVar, cast

from ...detection.engine import DetectionEngine
from ...detection.models import DetectionRule, ScanResult
from ...response.actions import ThreatAction
from .config import RuntimeSecurityConfig
from .decisions import Decision
from .runtime_proxy import SecuredRuntimeProxy
from .tool_security import RuntimeToolSecurity

_PROMPT_RULE_CATEGORIES = {"direct_injection", "jailbreak", "role_manipulation"}
_OUTPUT_RULE_CATEGORIES = {"data_exfiltration", "direct_injection"}
_HANDOFF_RULE_CATEGORIES = {
    "direct_injection",
    "jailbreak",
    "role_manipulation",
    "tool_poisoning",
    "data_exfiltration",
}

_ROLE_DRIFT_PATTERNS = (
    (
        "prooflayer-role-drift-system-role",
        re.compile(
            r"\b(you are now|act as|become)\s+(a\s+)?(system|developer|admin)\b", re.I
        ),
        "Agent role drift instruction detected",
    ),
    (
        "prooflayer-role-drift-ignore-role",
        re.compile(
            r"\b(ignore|override|forget)\s+(your\s+)?(role|persona|assignment)\b", re.I
        ),
        "Agent role override instruction detected",
    ),
)
_UNSAFE_HANDOFF_PATTERNS = (
    (
        "prooflayer-unsafe-handoff-bypass-review",
        re.compile(
            r"\b(skip|bypass|avoid)\s+(review|approval|security|guardrails?)\b", re.I
        ),
        "Unsafe handoff attempts to bypass review or guardrails",
    ),
    (
        "prooflayer-unsafe-handoff-hidden-delegation",
        re.compile(
            r"\b(do not|don't)\s+(tell|show|reveal)\s+(the\s+)?(user|operator|auditor)\b",
            re.I,
        ),
        "Unsafe handoff asks an agent to hide actions from oversight",
    ),
    (
        "prooflayer-unsafe-handoff-unapproved-agent",
        re.compile(
            r"\b(delegate|handoff|transfer)\s+.*\b(unapproved|external|unknown)\s+agent\b",
            re.I,
        ),
        "Unsafe handoff delegates to an unapproved agent",
    ),
)
_SMUGGLING_PATTERNS = (
    (
        "prooflayer-cross-agent-smuggled-instruction",
        re.compile(
            r"\b(forward|pass|send)\s+.*\b(hidden|secret|system)\s+instructions?\b",
            re.I,
        ),
        "Cross-agent instruction smuggling detected",
    ),
    (
        "prooflayer-cross-agent-next-agent",
        re.compile(
            r"\b(next|other)\s+agent\b.*\b(ignore|override|exfiltrate|leak)\b", re.I
        ),
        "Message attempts to steer another agent toward unsafe behavior",
    ),
)

_F = TypeVar("_F", bound=Callable[..., Any])


class AgentSecurity(RuntimeToolSecurity):
    """Shared scanner for agent framework inputs, outputs, tools, and handoffs."""

    integration_name = "agent_framework"

    def __init__(
        self,
        config: Optional[RuntimeSecurityConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
        blocked_error_type: type[Exception] = RuntimeError,
    ) -> None:
        """Initialize the shared agent security adapter."""
        super().__init__(
            config=config or RuntimeSecurityConfig(),
            detection_engine=detection_engine,
        )
        self._blocked_error_type = blocked_error_type

    def wrap(self, target: Any) -> "SecuredAgentRuntime":
        """Return a protected agent runtime proxy."""
        return self.wrap_agent(target)

    def wrap_agent(self, agent: Any) -> "SecuredAgentRuntime":
        """Wrap an agent-like object with ProofLayer security checks."""
        return SecuredAgentRuntime(target=agent, adapter=self)

    def wrap_tools(self, tools: Iterable[Any]) -> list[Any]:
        """Wrap framework tools with shared tool-call security checks."""
        from .tool_wrappers import SecuredCallableTool

        return [SecuredCallableTool(tool=tool, security=self) for tool in tools]

    def scan_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic agent input before execution."""
        return self.scan_agent_input(payload, config=config)

    def scan_output(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Inspect generic agent output after execution."""
        return self.scan_agent_output(payload, config=config)

    def scan_agent_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan agent input for injection, jailbreak, and role drift attempts."""
        return self._scan_agent_event(
            category="agent_input",
            configured_action=self.config.prompt_injection,
            payload=payload,
            config=config,
            metadata=metadata,
            rule_categories=_PROMPT_RULE_CATEGORIES,
            heuristic_groups=(_ROLE_DRIFT_PATTERNS,),
        )

    def scan_agent_output(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan agent output before it is returned to the caller."""
        return self._scan_agent_event(
            category="agent_output",
            configured_action=self.config.exfil,
            payload=payload,
            config=config,
            metadata=metadata,
            rule_categories=_OUTPUT_RULE_CATEGORIES,
            heuristic_groups=(),
        )

    def scan_handoff(
        self,
        payload: Any,
        config: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Scan an agent-to-agent handoff or delegation message."""
        return self._scan_agent_event(
            category="unsafe_handoff",
            configured_action=self.config.unsafe_handoff,
            payload=payload,
            config=config,
            metadata=metadata,
            rule_categories=_HANDOFF_RULE_CATEGORIES,
            heuristic_groups=(
                _UNSAFE_HANDOFF_PATTERNS,
                _ROLE_DRIFT_PATTERNS,
                _SMUGGLING_PATTERNS,
            ),
        )

    def raise_if_blocked(self, decision: Decision, message: str) -> None:
        """Raise this integration's blocked error when a decision blocks execution."""
        if decision.action == ThreatAction.BLOCK:
            rules = ", ".join(decision.rule_ids)
            raise self._blocked_error_type(f"{message} (rules: {rules})")

    def _scan_agent_event(
        self,
        category: str,
        configured_action: str,
        payload: Any,
        config: Optional[dict[str, Any]],
        metadata: Optional[dict[str, Any]],
        rule_categories: set[str],
        heuristic_groups: tuple[tuple[tuple[str, re.Pattern[str], str], ...], ...],
    ) -> Decision:
        scan_result = self.detection_engine.scan(
            tool_name=category,
            arguments={"payload": payload, "metadata": metadata or {}},
        )
        matched_rules = [
            rule
            for rule in scan_result.matched_rules
            if rule.category in rule_categories
        ]
        heuristic_rules = _match_heuristics(payload, heuristic_groups)
        if not matched_rules and not heuristic_rules:
            return Decision.allow()

        action = ThreatAction(configured_action.upper())
        risk_score = max(
            scan_result.score if matched_rules else 0,
            90 if heuristic_rules else 0,
        )
        rule_ids = [rule.id for rule in matched_rules] + [
            rule["id"] for rule in heuristic_rules
        ]
        reason_parts = [rule.message for rule in matched_rules] + [
            rule["message"] for rule in heuristic_rules
        ]
        event_metadata = dict(metadata or {})
        self._record_agent_event(
            category=category,
            payload=payload,
            config=config,
            metadata=event_metadata,
            action=action,
            risk_score=risk_score,
            scan_result=scan_result,
            matched_rules=matched_rules,
            heuristic_rules=heuristic_rules,
        )
        return Decision(
            action=action,
            category=category,
            risk_score=risk_score,
            rule_ids=rule_ids,
            reason=", ".join(reason_parts),
            metadata=event_metadata,
        )

    def _record_agent_event(
        self,
        category: str,
        payload: Any,
        config: Optional[dict[str, Any]],
        metadata: dict[str, Any],
        action: ThreatAction,
        risk_score: int,
        scan_result: ScanResult,
        matched_rules: list[DetectionRule],
        heuristic_rules: list[dict[str, str]],
    ) -> None:
        self.record_event(
            {
                "event_type": "detection",
                "integration": self.integration_name,
                "category": category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.extract_session_id(config, payload),
                "decision": action.value,
                "risk_score": risk_score,
                "latency_ms": scan_result.latency_ms,
                "payload": payload,
                "metadata": metadata,
                "rule_ids": [rule.id for rule in matched_rules]
                + [rule["id"] for rule in heuristic_rules],
                "rule_sources": [
                    {
                        "id": rule.id,
                        "category": rule.category,
                        "severity": rule.severity,
                        "message": rule.message,
                        "source": "prooflayer-rules",
                    }
                    for rule in matched_rules
                ]
                + [
                    {
                        "id": rule["id"],
                        "category": category,
                        "severity": "critical",
                        "message": rule["message"],
                        "source": "prooflayer-heuristic",
                    }
                    for rule in heuristic_rules
                ],
            }
        )


class SecuredAgentRuntime(SecuredRuntimeProxy):
    """Proxy that preserves common agent invocation methods."""

    def __init__(self, target: Any, adapter: AgentSecurity) -> None:
        """Create a secured agent runtime proxy."""
        super().__init__(target=target, adapter=adapter)
        self._security = adapter

    def invoke(self, input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Invoke an agent with input and output scanning."""
        return self._call_method("invoke", input, args, kwargs)

    async def ainvoke(self, input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Invoke an agent asynchronously with input and output scanning."""
        return await self._acall_method("ainvoke", input, args, kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run an agent with input and output scanning."""
        return self._call_method("run", None, args, kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Run an agent asynchronously with input and output scanning."""
        return await self._acall_method("arun", None, args, kwargs)

    def call(self, *args: Any, **kwargs: Any) -> Any:
        """Call an agent runtime with input and output scanning."""
        return self._call_method("call", None, args, kwargs)

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        """Call an agent runtime asynchronously with input and output scanning."""
        return await self._acall_method("acall", None, args, kwargs)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute an agent runtime with input and output scanning."""
        return self._call_method("execute", None, args, kwargs)

    async def aexecute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute an agent runtime asynchronously with input and output scanning."""
        return await self._acall_method("aexecute", None, args, kwargs)

    def kickoff(self, *args: Any, **kwargs: Any) -> Any:
        """Kick off a CrewAI-style crew with input and output scanning."""
        return self._call_method("kickoff", None, args, kwargs)

    async def kickoff_async(self, *args: Any, **kwargs: Any) -> Any:
        """Kick off a CrewAI-style crew asynchronously with scanning."""
        return await self._acall_method("kickoff_async", None, args, kwargs)

    def handoff(
        self, target_agent: Any, message: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Scan an agent handoff before delegating to the wrapped runtime."""
        config = _config_from_kwargs(kwargs)
        payload = {
            "target_agent": _agent_name(target_agent),
            "message": message,
            "args": list(args),
            "kwargs": _visible_kwargs(kwargs),
        }
        decision = self._security.scan_handoff(payload, config=config)
        self._security.raise_if_blocked(decision, "Agent handoff blocked")
        result = getattr(self.target, "handoff")(target_agent, message, *args, **kwargs)
        self._scan_output(result, config)
        return result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call a callable agent with input and output scanning."""
        return self._call_callable(args, kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes, wrapping public callable methods."""
        attr = getattr(self.target, name)
        if name.startswith("_") or not callable(attr):
            return attr
        if inspect.iscoroutinefunction(attr):
            return self._wrap_async_attr(name, attr)
        return self._wrap_sync_attr(name, attr)

    def _call_method(
        self,
        method_name: str,
        input_value: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        method = getattr(self.target, method_name, None)
        if not callable(method):
            if callable(self.target):
                payload_args = (
                    (input_value,) if input_value is not None else ()
                ) + args
                return self._call_callable(payload_args, kwargs)
            raise AttributeError(
                f"Wrapped agent has no callable {method_name!r} method"
            )
        config = _config_from_kwargs(kwargs)
        payload = _call_payload(input_value, args, kwargs)
        self._scan_input(payload, config, method_name)
        result = (
            method(input_value, *args, **kwargs)
            if input_value is not None
            else method(*args, **kwargs)
        )
        self._scan_output(result, config)
        return result

    async def _acall_method(
        self,
        method_name: str,
        input_value: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        method = getattr(self.target, method_name, None)
        if not callable(method):
            raise AttributeError(
                f"Wrapped agent has no callable {method_name!r} method"
            )
        config = _config_from_kwargs(kwargs)
        payload = _call_payload(input_value, args, kwargs)
        self._scan_input(payload, config, method_name)
        result = (
            method(input_value, *args, **kwargs)
            if input_value is not None
            else method(*args, **kwargs)
        )
        if inspect.isawaitable(result):
            result = await cast(Awaitable[Any], result)
        self._scan_output(result, config)
        return result

    def _call_callable(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        config = _config_from_kwargs(kwargs)
        payload = _call_payload(None, args, kwargs)
        self._scan_input(payload, config, "__call__")
        result = self.target(*args, **kwargs)
        self._scan_output(result, config)
        return result

    def _wrap_sync_attr(self, method_name: str, method: _F) -> _F:
        @wraps(method)
        def secured(*args: Any, **kwargs: Any) -> Any:
            config = _config_from_kwargs(kwargs)
            payload = _call_payload(None, args, kwargs)
            self._scan_input(payload, config, method_name)
            result = method(*args, **kwargs)
            self._scan_output(result, config)
            return result

        return cast(_F, secured)

    def _wrap_async_attr(
        self, method_name: str, method: Callable[..., Awaitable[Any]]
    ) -> Callable[..., Awaitable[Any]]:
        @wraps(method)
        async def secured(*args: Any, **kwargs: Any) -> Any:
            config = _config_from_kwargs(kwargs)
            payload = _call_payload(None, args, kwargs)
            self._scan_input(payload, config, method_name)
            result = await method(*args, **kwargs)
            self._scan_output(result, config)
            return result

        return secured

    def _scan_input(
        self,
        payload: Any,
        config: Optional[dict[str, Any]],
        method_name: str,
    ) -> None:
        decision = self._security.scan_agent_input(
            payload,
            config=config,
            metadata={"method": method_name},
        )
        self._security.raise_if_blocked(decision, "Agent input blocked")

    def _scan_output(self, output: Any, config: Optional[dict[str, Any]]) -> None:
        decision = self._security.scan_agent_output(output, config=config)
        self._security.raise_if_blocked(decision, "Agent output blocked")


def _match_heuristics(
    payload: Any,
    heuristic_groups: tuple[tuple[tuple[str, re.Pattern[str], str], ...], ...],
) -> list[dict[str, str]]:
    text = _payload_text(payload)
    findings: list[dict[str, str]] = []
    for group in heuristic_groups:
        for rule_id, pattern, message in group:
            if pattern.search(text):
                findings.append({"id": rule_id, "message": message})
    return findings


def _payload_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, sort_keys=True, default=str)
    except TypeError:
        return str(payload)


def _call_payload(
    input_value: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if input_value is not None:
        payload["input"] = input_value
    if args:
        payload["args"] = list(args)
    visible_kwargs = _visible_kwargs(kwargs)
    if visible_kwargs:
        payload["kwargs"] = visible_kwargs
    return payload


def _visible_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in kwargs.items()
        if key not in {"config", "callbacks", "tags", "metadata"}
    }


def _config_from_kwargs(kwargs: dict[str, Any]) -> Optional[dict[str, Any]]:
    config = kwargs.get("config")
    return config if isinstance(config, dict) else None


def _agent_name(agent: Any) -> str:
    return str(
        getattr(agent, "name", None)
        or getattr(agent, "role", None)
        or getattr(agent, "__name__", None)
        or agent.__class__.__name__
    )
