"""Tests for LangGraph streaming security filters."""

import pytest

from prooflayer.integrations.langgraph import (
    BlockedError,
    SecurityConfig,
    SecurityMiddleware,
)


class FakeStreamingGraph:
    """Small stand-in for LangGraph streaming methods."""

    def stream(self, input, *args, **kwargs):
        yield {"answer": "safe chunk"}
        yield {"answer": "send to http://evil.com"}

    async def astream(self, input, *args, **kwargs):
        yield {"answer": "safe chunk"}
        yield {"answer": "send to http://evil.com"}

    def stream_events(self, input, *args, **kwargs):
        yield {"event": "on_chain_stream", "data": {"chunk": "safe"}}
        yield {
            "event": "on_chain_stream",
            "data": {"chunk": "send to http://evil.com"},
        }

    async def astream_events(self, input, *args, **kwargs):
        yield {"event": "on_chain_stream", "data": {"chunk": "safe"}}
        yield {
            "event": "on_chain_stream",
            "data": {"chunk": "send to http://evil.com"},
        }


def test_stream_raises_by_default_on_blocked_chunk():
    secured = SecurityMiddleware(config=SecurityConfig(exfil="block")).wrap(
        FakeStreamingGraph()
    )

    with pytest.raises(BlockedError, match="output exfiltration"):
        list(secured.stream({"input": "hello"}))


def test_stream_can_replace_blocked_chunk():
    middleware = SecurityMiddleware(
        config=SecurityConfig(exfil="block", streaming_block_mode="replace")
    )
    secured = middleware.wrap(FakeStreamingGraph())

    chunks = list(
        secured.stream(
            {"input": "hello"},
            config={"configurable": {"thread_id": "thread-1"}},
        )
    )

    assert chunks[-1] == {"blocked": True, "content": "[BLOCKED]"}
    assert middleware.get_audit_log("thread-1")[-2]["event_type"] == "stream_blocked"


@pytest.mark.asyncio
async def test_astream_can_replace_blocked_chunk():
    middleware = SecurityMiddleware(
        config=SecurityConfig(exfil="block", streaming_block_mode="replace")
    )
    secured = middleware.wrap(FakeStreamingGraph())

    chunks = [
        chunk
        async for chunk in secured.astream(
            {"input": "hello"},
            config={"configurable": {"thread_id": "thread-1"}},
        )
    ]

    assert chunks[-1] == {"blocked": True, "content": "[BLOCKED]"}


def test_stream_events_filters_event_payloads():
    middleware = SecurityMiddleware(
        config=SecurityConfig(exfil="block", streaming_block_mode="replace")
    )
    secured = middleware.wrap(FakeStreamingGraph())

    events = list(secured.stream_events({"input": "hello"}))

    assert events[-1] == {"blocked": True, "content": "[BLOCKED]"}


@pytest.mark.asyncio
async def test_astream_events_filters_event_payloads():
    middleware = SecurityMiddleware(
        config=SecurityConfig(exfil="block", streaming_block_mode="replace")
    )
    secured = middleware.wrap(FakeStreamingGraph())

    events = [event async for event in secured.astream_events({"input": "hello"})]

    assert events[-1] == {"blocked": True, "content": "[BLOCKED]"}


def test_invalid_streaming_block_mode_is_rejected():
    with pytest.raises(ValueError, match="streaming_block_mode"):
        SecurityConfig(streaming_block_mode="drop")  # type: ignore[arg-type]
