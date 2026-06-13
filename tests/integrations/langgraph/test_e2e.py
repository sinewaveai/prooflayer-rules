"""End-to-end tests for the LangGraph integration."""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from prooflayer.integrations.langgraph import SecurityMiddleware


class EchoState(TypedDict):
    """State for minimal LangGraph tests."""

    text: str


def echo_node(state: EchoState) -> EchoState:
    """Return the input state unchanged."""
    return {"text": state["text"]}


def test_security_middleware_wraps_real_langgraph_invoke():
    graph = StateGraph(EchoState)
    graph.add_node("echo", echo_node)
    graph.add_edge(START, "echo")
    graph.add_edge("echo", END)
    secured = SecurityMiddleware().wrap(graph.compile())

    result = secured.invoke({"text": "hello"})

    assert result == {"text": "hello"}


def test_security_middleware_records_before_and_after_events_for_real_graph():
    graph = StateGraph(EchoState)
    graph.add_node("echo", echo_node)
    graph.add_edge(START, "echo")
    graph.add_edge("echo", END)
    middleware = SecurityMiddleware()
    secured = middleware.wrap(graph.compile())

    secured.invoke(
        {"text": "hello"},
        config={"configurable": {"thread_id": "thread-1"}},
    )

    event_types = [event["event_type"] for event in middleware.get_audit_log()]
    assert event_types == ["before_node", "after_node"]
    assert middleware.get_audit_log("thread-1")[0]["node_name"] == "__graph__"
