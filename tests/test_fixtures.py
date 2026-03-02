"""Fixture-based parametrized tests for ProofLayer detection engine."""
import json
import pytest
from pathlib import Path
from prooflayer.detection.engine import DetectionEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name):
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class TestBenignFixtures:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = DetectionEngine()

    @pytest.mark.parametrize(
        "case",
        load_fixture("benign_tool_calls.json"),
        ids=lambda c: c.get("tool_name", "unknown"),
    )
    def test_benign_score_below_threshold(self, case):
        result = self.engine.scan(
            tool_name=case["tool_name"], arguments=case["arguments"]
        )
        score, _ = result  # backwards compat iteration
        assert score < case["max_expected_score"], (
            f"Benign call '{case['tool_name']}' scored {score}, "
            f"expected < {case['max_expected_score']}. "
            f"Args: {case['arguments']}"
        )


class TestMaliciousFixtures:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = DetectionEngine()

    @pytest.mark.parametrize(
        "case",
        load_fixture("malicious_payloads.json"),
        ids=lambda c: c.get("tool_name", "unknown") + "-" + c.get("category", ""),
    )
    def test_malicious_score_above_threshold(self, case):
        result = self.engine.scan(
            tool_name=case["tool_name"], arguments=case["arguments"]
        )
        score, _ = result
        assert score >= case["min_expected_score"], (
            f"Malicious call '{case['tool_name']}' ({case['category']}) "
            f"scored {score}, expected >= {case['min_expected_score']}. "
            f"Args: {case['arguments']}"
        )


class TestMCPMessageParsing:
    """Test parsing of raw JSON-RPC MCP messages."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = DetectionEngine()

    @pytest.mark.parametrize(
        "case",
        load_fixture("mcp_messages.json"),
        ids=lambda c: c.get("description", "unknown"),
    )
    def test_mcp_message_extraction(self, case):
        msg = case["message"]
        method = msg.get("method", "")
        params = msg.get("params", {})

        # Only tools/call messages have tool_name and arguments to scan
        if method == "tools/call" and "name" in params:
            tool_name = params["name"]
            arguments = params.get("arguments", {})
            assert tool_name == case["expected_tool_name"]

            result = self.engine.scan(tool_name=tool_name, arguments=arguments)
            score, _ = result

            if case["expected_benign"]:
                assert score < 30, (
                    f"MCP message '{case['description']}' scored {score}, "
                    f"expected benign (< 30)"
                )
            else:
                assert score >= 30, (
                    f"MCP message '{case['description']}' scored {score}, "
                    f"expected malicious (>= 30)"
                )
        else:
            # Non-tool-call messages should not have a tool_name
            assert case["expected_tool_name"] is None, (
                f"Non-tool-call message '{case['description']}' should have "
                f"expected_tool_name=null"
            )
