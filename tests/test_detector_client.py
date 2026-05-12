import httpx

from prooflayer.detection.detector_client import (
    ExternalDetectorClient,
    apply_detector_result,
)
from prooflayer.detection.models import ScanResult


def test_detector_client_posts_runtime_event_and_parses_result():
    captured = {}

    def handler(request):
        captured["json"] = request.read().decode()
        return httpx.Response(
            200,
            json={
                "label": "adversarial",
                "score": 0.91,
                "categories": ["prompt_injection"],
                "reasons": ["instruction override"],
                "model": "gpt-4.1-mini",
            },
        )

    client = httpx.Client(
        base_url="http://detector.local",
        transport=httpx.MockTransport(handler),
    )
    detector = ExternalDetectorClient(
        base_url="http://detector.local",
        http_client=client,
    )

    result = detector.scan(
        tool_name="config.read",
        arguments={"prompt": "Ignore previous instructions", "path": "/internal"},
        metadata={"trace_id": "trace-123"},
    )

    assert result is not None
    assert result.label == "adversarial"
    assert result.risk_score == 91
    assert result.categories == ["prompt_injection"]
    assert '"trace_id":"trace-123"' in captured["json"]


def test_detector_client_returns_none_on_timeout_for_graceful_degradation():
    def handler(request):
        raise httpx.TimeoutException("detector timed out")

    client = httpx.Client(
        base_url="http://detector.local",
        transport=httpx.MockTransport(handler),
    )
    detector = ExternalDetectorClient(
        base_url="http://detector.local",
        http_client=client,
    )

    result = detector.scan(tool_name="search", arguments={"query": "benign"})

    assert result is None


def test_detector_client_returns_none_on_schema_invalid_response():
    def handler(request):
        return httpx.Response(200, json={"label": "adversarial"})

    client = httpx.Client(
        base_url="http://detector.local",
        transport=httpx.MockTransport(handler),
    )
    detector = ExternalDetectorClient(
        base_url="http://detector.local",
        http_client=client,
    )

    result = detector.scan(tool_name="search", arguments={"query": "benign"})

    assert result is None


def test_apply_detector_result_ignores_benign_detector_score():
    scan_result = ScanResult(
        score=5,
        level="SAFE",
        action="ALLOW",
        matched_rules=[],
        scoring_breakdown={"pattern_score": 5},
        tool_name="search",
        arguments={"query": "benign"},
    )
    detector = ExternalDetectorClient.DetectorResult(
        label="benign",
        score=0.91,
        risk_score=91,
        categories=[],
        reasons=[],
        model="gpt-4.1-mini",
    )

    apply_detector_result(scan_result, detector)

    assert scan_result.score == 5
    assert scan_result.level == "SAFE"
    assert scan_result.action == "ALLOW"
    assert "detector_score" not in scan_result.scoring_breakdown


def test_apply_detector_result_raises_score_and_adds_synthetic_rule():
    scan_result = ScanResult(
        score=5,
        level="SAFE",
        action="ALLOW",
        matched_rules=[],
        scoring_breakdown={"pattern_score": 5},
        tool_name="config.read",
        arguments={"prompt": "Ignore previous instructions"},
    )
    detector = ExternalDetectorClient.DetectorResult(
        label="adversarial",
        score=0.91,
        risk_score=91,
        categories=["prompt_injection"],
        reasons=["instruction override"],
        model="gpt-4.1-mini",
    )

    returned = apply_detector_result(scan_result, detector)

    assert returned is None
    assert scan_result.score == 91
    assert scan_result.level == "THREAT"
    assert scan_result.action == "BLOCK"
    assert scan_result.scoring_breakdown["detector_score"] == 91
    assert scan_result.matched_rules[0].id == "external-detector-adversarial"
    # Synthetic rule tags OWASP from the detector category, not a hardcoded constant.
    assert scan_result.matched_rules[0].owasp == ["LLM01"]


def test_apply_detector_result_maps_data_exfiltration_to_llm02():
    scan_result = ScanResult(
        score=0,
        level="SAFE",
        action="ALLOW",
        matched_rules=[],
        scoring_breakdown={"pattern_score": 0},
        tool_name="leak",
        arguments={"path": "/etc/passwd"},
    )
    detector = ExternalDetectorClient.DetectorResult(
        label="adversarial",
        score=0.8,
        risk_score=80,
        categories=["data_exfiltration"],
        reasons=["sensitive path"],
        model="gpt-4.1-mini",
    )

    apply_detector_result(scan_result, detector)

    assert scan_result.matched_rules[0].owasp == ["LLM02"]


def test_external_detector_client_does_not_open_socket_when_disabled():
    detector = ExternalDetectorClient(
        base_url="http://detector.local",
        enabled=False,
    )

    result = detector.scan(tool_name="search", arguments={"query": "benign"})

    assert result is None
    # Disabled clients never construct an httpx.Client.
    assert detector._client is None
    detector.close()  # idempotent, safe even when nothing was opened


def test_external_detector_client_close_releases_owned_client():
    detector = ExternalDetectorClient(base_url="http://detector.local")

    # Force lazy construction so close has something to release.
    detector._get_client()
    assert detector._client is not None

    detector.close()
    assert detector._client is None
    # Calling close again must be safe.
    detector.close()


def test_extract_prompt_decodes_utf8_bytes_in_argument_values():
    body = ExternalDetectorClient._extract_prompt({"prompt": "hello".encode("utf-8")})
    assert body == "hello"
