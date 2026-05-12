import asyncio
import sys
import types

from prooflayer.detection.detector_client import ExternalDetectorClient
from prooflayer.runtime import mcp_wrapper


class BlockingDetector:
    def scan(self, tool_name, arguments, metadata=None):
        return ExternalDetectorClient.DetectorResult(
            label="adversarial",
            score=0.95,
            risk_score=95,
            categories=["prompt_injection"],
            reasons=["model classified event as adversarial"],
            model="gpt-4.1-mini",
        )


class AsyncBlockingDetector:
    def __init__(self):
        self.sync_calls = 0
        self.async_calls = 0

    def scan(self, tool_name, arguments, metadata=None):
        self.sync_calls += 1
        raise AssertionError(
            "MCP wrapper must use scan_async to avoid blocking the event loop"
        )

    async def scan_async(self, tool_name, arguments, metadata=None):
        self.async_calls += 1
        return ExternalDetectorClient.DetectorResult(
            label="adversarial",
            score=0.95,
            risk_score=95,
            categories=["prompt_injection"],
            reasons=["model classified event as adversarial"],
            model="gpt-4.1-mini",
        )


class FakeServer:
    def __init__(self):
        self.registered_handler = None

    def call_tool(self):
        def decorator(handler):
            self.registered_handler = handler
            return handler

        return decorator


async def _handler(name, arguments):
    return {"ok": True}


def test_mcp_wrapper_applies_external_detector_before_tool_handler(monkeypatch, tmp_path):
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")

    class TextContent:
        def __init__(self, type, text):
            self.type = type
            self.text = text

    class CallToolResult:
        def __init__(self, content, isError):
            self.content = content
            self.isError = isError

    fake_types.TextContent = TextContent
    fake_types.CallToolResult = CallToolResult
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.types", fake_types)
    monkeypatch.setattr(mcp_wrapper, "_check_mcp_available", lambda: True)

    wrapper = mcp_wrapper.ProofLayerMCPWrapper(
        action_on_threat="block",
        report_dir=str(tmp_path),
        detector_client=BlockingDetector(),
        scan_tool_outputs=False,
    )
    server = FakeServer()

    wrapper._wrap_call_tool(server)
    server.call_tool()(_handler)
    result = asyncio.run(server.registered_handler("config.read", {"prompt": "hello"}))

    assert result.isError is True
    assert "blocked" in result.content[0].text.lower()


def test_mcp_wrapper_prefers_scan_async_over_blocking_scan(monkeypatch, tmp_path):
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")

    class TextContent:
        def __init__(self, type, text):
            self.type = type
            self.text = text

    class CallToolResult:
        def __init__(self, content, isError):
            self.content = content
            self.isError = isError

    fake_types.TextContent = TextContent
    fake_types.CallToolResult = CallToolResult
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.types", fake_types)
    monkeypatch.setattr(mcp_wrapper, "_check_mcp_available", lambda: True)

    detector = AsyncBlockingDetector()
    wrapper = mcp_wrapper.ProofLayerMCPWrapper(
        action_on_threat="block",
        report_dir=str(tmp_path),
        detector_client=detector,
        scan_tool_outputs=False,
    )
    server = FakeServer()

    wrapper._wrap_call_tool(server)
    server.call_tool()(_handler)
    result = asyncio.run(server.registered_handler("config.read", {"prompt": "hello"}))

    assert detector.async_calls == 1
    assert detector.sync_calls == 0
    assert result.isError is True


def test_mcp_wrapper_preserves_fail_closed_from_config(monkeypatch, tmp_path):
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")
    fake_types.TextContent = type("TextContent", (), {})
    fake_types.CallToolResult = type("CallToolResult", (), {})
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.types", fake_types)
    monkeypatch.setattr(mcp_wrapper, "_check_mcp_available", lambda: True)

    wrapper = mcp_wrapper.ProofLayerMCPWrapper(
        config={
            "detection": {
                "enabled": True,
                "rules_dir": None,
                "fail_closed": False,
                "score_threshold": {
                    "allow": (0, 29),
                    "warn": (30, 69),
                    "block": (70, 100),
                },
            },
            "response": {
                "on_threat": "warn",
                "report_dir": str(tmp_path),
            },
        }
    )

    assert wrapper.config["detection"]["fail_closed"] is False
