"""Tests for LangGraph audit checkpointing."""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from prooflayer.integrations.langgraph import AuditCheckpointer


class EchoState(TypedDict):
    """State for minimal LangGraph tests."""

    text: str


def echo_node(state: EchoState) -> EchoState:
    """Return the input state unchanged."""
    return {"text": state["text"]}


def test_audit_checkpointer_records_langgraph_checkpoints():
    graph = StateGraph(EchoState)
    graph.add_node("echo", echo_node)
    graph.add_edge(START, "echo")
    graph.add_edge("echo", END)
    checkpointer = AuditCheckpointer()
    compiled = graph.compile(checkpointer=checkpointer)

    result = compiled.invoke(
        {"text": "hello"},
        config={"configurable": {"thread_id": "thread-1"}},
    )

    assert result == {"text": "hello"}
    assert any(
        event["event_type"] == "checkpoint_put"
        and event["thread_id"] == "thread-1"
        for event in checkpointer.audit_log
    )
