"""Tests for LangGraph eval target adapters."""

import pytest

from prooflayer.evals import LangGraphEvalTarget


class FakeGraph:
    """Small graph stand-in for eval target tests."""

    def invoke(self, payload, **kwargs):
        """Return a dict shaped like a common LangGraph result."""
        return {"answer": f"echo:{payload['input']}"}

    async def ainvoke(self, payload, **kwargs):
        """Return an async dict result."""
        return {"text": f"async:{payload['input']}"}


def test_langgraph_target_invokes_graph_and_extracts_text():
    target = LangGraphEvalTarget(FakeGraph(), name="demo")

    assert target.invoke("hello") == "echo:hello"


@pytest.mark.asyncio
async def test_langgraph_target_async_invocation_extracts_text():
    target = LangGraphEvalTarget(FakeGraph())

    assert await target.ainvoke("hello") == "async:hello"


def test_langgraph_target_handles_chat_completion_shape():
    target = LangGraphEvalTarget(FakeGraph(), name="demo")

    response = target.handle_chat_completions(
        {"model": "demo", "messages": [{"role": "user", "content": "hello"}]}
    )

    assert response["object"] == "chat.completion"
    assert response["choices"][0]["message"]["content"] == "echo:hello"
