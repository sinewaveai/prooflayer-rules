"""Tests for the LangGraph security middleware."""

import pytest

from prooflayer.integrations.langgraph import SecurityConfig, SecurityMiddleware
from prooflayer.response.actions import ThreatAction


class FakeCompiledGraph:
    """Small stand-in for a compiled LangGraph."""

    graph_name = "fake"

    def __init__(self) -> None:
        self.invocations = []

    def invoke(self, input, *args, **kwargs):
        self.invocations.append(input)
        return {"session_id": "session-1", "input": input}

    def stream(self, input, *args, **kwargs):
        yield {"chunk": input}


def test_security_config_defaults_cover_all_detection_categories():
    config = SecurityConfig()

    assert config.category_actions() == {
        "prompt_injection": "warn",
        "jailbreak": "warn",
        "tool_abuse": "warn",
        "exfil": "warn",
        "scope_drift": "warn",
        "state_manipulation": "warn",
        "multi_turn": "warn",
    }
    assert config.emit_to == ["stdout"]


def test_security_config_accepts_customer_facing_options():
    config = SecurityConfig(
        prompt_injection="block",
        tool_abuse="block",
        exfil="block",
        scope_drift="warn",
        multi_turn="allow",
        compliance_frameworks=["nist_ai_rmf", "soc2"],
        emit_to=["stdout", "logfile:./audit.jsonl"],
        allowed_tools=["search_docs"],
    )

    assert config.prompt_injection == "block"
    assert config.compliance_frameworks == ["nist_ai_rmf", "soc2"]
    assert config.allowed_tools == ["search_docs"]


def test_security_config_rejects_invalid_detection_action():
    with pytest.raises(ValueError, match="prompt_injection"):
        SecurityConfig(prompt_injection="kill")  # type: ignore[arg-type]


def test_security_config_rejects_unknown_compliance_framework():
    with pytest.raises(ValueError, match="Unsupported compliance framework"):
        SecurityConfig(compliance_frameworks=["pci"])


def test_security_config_rejects_invalid_audit_sink():
    with pytest.raises(ValueError, match="Unsupported audit sink"):
        SecurityConfig(emit_to=["file"])


def test_security_middleware_wrap_invokes_underlying_graph():
    graph = FakeCompiledGraph()
    middleware = SecurityMiddleware()

    secured = middleware.wrap(graph)
    result = secured.invoke({"input": "hello"})

    assert result["input"] == {"input": "hello"}
    assert graph.invocations == [{"input": "hello"}]


def test_security_middleware_delegates_unknown_attributes():
    secured = SecurityMiddleware().wrap(FakeCompiledGraph())

    assert secured.graph_name == "fake"


def test_security_middleware_stubs_allow_scans():
    middleware = SecurityMiddleware()

    assert middleware.scan_input({"input": "hello"}) == ThreatAction.ALLOW
    assert middleware.scan_output({"answer": "hello"}) == ThreatAction.ALLOW


def test_security_middleware_stream_preserves_chunks():
    secured = SecurityMiddleware().wrap(FakeCompiledGraph())

    assert list(secured.stream({"input": "hello"})) == [
        {"chunk": {"input": "hello"}}
    ]


def test_get_audit_log_returns_copy_and_filters_by_session():
    middleware = SecurityMiddleware()
    middleware._audit_log.append({"session_id": "one", "event": "a"})
    middleware._audit_log.append({"session_id": "two", "event": "b"})

    all_events = middleware.get_audit_log()
    all_events.append({"session_id": "three", "event": "c"})

    assert middleware.get_audit_log("one") == [{"session_id": "one", "event": "a"}]
    assert len(middleware.get_audit_log()) == 2
