"""Reusable helpers for ProofLayer integration tests."""

from typing import Any


class FakeRuntime:
    """Small runtime stand-in that records invocations."""

    runtime_name = "fake-runtime"

    def __init__(self, result: Any = None) -> None:
        """Create a fake runtime with an optional result payload."""
        self.result = result if result is not None else {"ok": True}
        self.invocations: list[Any] = []

    def invoke(self, payload: Any, *args: Any, **kwargs: Any) -> Any:
        """Record and return a deterministic invocation result."""
        self.invocations.append(
            {
                "payload": payload,
                "args": args,
                "kwargs": kwargs,
            }
        )
        return self.result


def assert_hashed_event(event: dict[str, Any]) -> None:
    """Assert that an audit event has chain-of-custody hash fields."""
    assert event["hash"].startswith("sha256:")
    assert event["event_hash"]
    assert "previous_hash" in event
