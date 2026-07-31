"""Tests for shared ProofLayer integration primitives."""

import pytest

from prooflayer.integrations.common import (
    Decision,
    RuntimeSecurityConfig,
    SecuredRuntimeProxy,
    SecurityEnvelope,
    ToolCallEvent,
)
from prooflayer.integrations.common.audit import AuditEventRecorder
from prooflayer.integrations.common.envelope import extract_config_session_id
from prooflayer.response.actions import ThreatAction
from tests.integrations.common.helpers import FakeRuntime, assert_hashed_event


def test_runtime_security_config_defaults_cover_common_categories():
    """RuntimeSecurityConfig exposes common categories for future adapters."""
    config = RuntimeSecurityConfig()

    assert config.category_actions()["prompt_injection"] == "warn"
    assert config.category_actions()["command_injection"] == "block"
    assert config.category_actions()["unsafe_handoff"] == "warn"
    assert config.emit_to == ["stdout"]


def test_runtime_security_config_rejects_invalid_action():
    """RuntimeSecurityConfig validates detection actions."""
    with pytest.raises(ValueError, match="prompt_injection"):
        RuntimeSecurityConfig(prompt_injection="kill")  # type: ignore[arg-type]


def test_runtime_security_config_rejects_invalid_limit():
    """RuntimeSecurityConfig validates numeric limits."""
    with pytest.raises(ValueError, match="max_tool_calls_per_turn"):
        RuntimeSecurityConfig(max_tool_calls_per_turn=0)


def test_security_envelope_serializes_runtime_activity():
    """SecurityEnvelope keeps integration events structured."""
    envelope = SecurityEnvelope(
        integration="test_runtime",
        event_type="tool_call",
        session_id="session-1",
        actor="agent",
        tool_name="search",
        payload={"query": "hello"},
    )

    assert envelope.to_dict()["integration"] == "test_runtime"
    assert envelope.to_dict()["payload"] == {"query": "hello"}


def test_tool_call_event_serializes_tool_activity():
    """ToolCallEvent preserves tool names and arguments."""
    event = ToolCallEvent(
        integration="test_runtime",
        tool_name="search",
        arguments={"query": "hello"},
    )

    assert event.to_dict()["tool_name"] == "search"
    assert event.to_dict()["arguments"] == {"query": "hello"}


def test_decision_serializes_threat_action_value():
    """Decision serializes ThreatAction as a string value."""
    decision = Decision(
        action=ThreatAction.BLOCK,
        category="tool_abuse",
        risk_score=90,
        rule_ids=["rule-1"],
    )

    assert decision.to_dict()["action"] == "BLOCK"
    assert decision.to_dict()["rule_ids"] == ["rule-1"]


def test_audit_event_recorder_hashes_and_filters_events():
    """AuditEventRecorder adds chain hashes and filters by session."""
    recorder = AuditEventRecorder()

    first = recorder.append({"event_type": "detection", "session_id": "one"})
    second = recorder.append({"event_type": "detection", "session_id": "two"})

    assert_hashed_event(first)
    assert second["previous_hash"] == first["event_hash"]
    assert recorder.list("one") == [first]
    assert recorder.list()[1] == second


def test_audit_event_recorder_returns_copies():
    """AuditEventRecorder callers cannot mutate stored events through results."""
    recorder = AuditEventRecorder()
    recorder.append({"event_type": "detection", "session_id": "one"})

    events = recorder.list()
    events[0]["session_id"] = "mutated"

    assert recorder.list()[0]["session_id"] == "one"


def test_extract_config_session_id_prefers_configurable_values():
    """Session extraction supports LangGraph-style config conventions."""
    session_id = extract_config_session_id(
        "session_id",
        {"configurable": {"thread_id": "thread-1"}},
        {"session_id": "payload-session"},
    )

    assert session_id == "thread-1"


def test_secured_runtime_proxy_delegates_unknown_attributes():
    """SecuredRuntimeProxy delegates attributes to wrapped runtimes."""

    proxy = SecuredRuntimeProxy(FakeRuntime(), adapter=object())

    assert proxy.runtime_name == "fake-runtime"
