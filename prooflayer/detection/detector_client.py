"""Client for the optional proprietary ProofLayer detector service."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from .models import DetectionRule, ScanResult

logger = logging.getLogger(__name__)


class ExternalDetectorClient:
    """HTTP client for a local `prooflayer-detector` service."""

    @dataclass(frozen=True)
    class DetectorResult:
        label: str
        score: float
        risk_score: int
        categories: list[str]
        reasons: list[str]
        model: str

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8088",
        timeout_ms: int = 250,
        enabled: bool = True,
        http_client: Optional[httpx.Client] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_ms = timeout_ms
        self.enabled = enabled
        self._client = http_client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout_ms / 1000,
        )

    def scan(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectorResult]:
        """Send one runtime event to the external detector.

        Returns None on timeout, connection failure, invalid response, or when
        disabled. Runtime security gracefully degrades to rules-only mode.
        """
        if not self.enabled:
            return None

        body = {
            "prompt": self._extract_prompt(arguments),
            "tool_name": tool_name,
            "tool_arguments": arguments,
            "metadata": metadata or {},
        }

        try:
            response = self._client.post(
                "/v1/detect",
                content=json.dumps(body, separators=(",", ":"), default=str),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
            return self._parse_result(payload)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            logger.warning("External detector unavailable; using rules-only mode: %s", exc)
            return None

    def _parse_result(self, payload: Dict[str, Any]) -> DetectorResult:
        label = str(payload["label"])
        if label not in {"benign", "suspicious", "adversarial"}:
            raise ValueError(f"invalid detector label: {label}")

        categories = payload.get("categories", [])
        reasons = payload.get("reasons", [])
        if not isinstance(categories, list) or not isinstance(reasons, list):
            raise ValueError("detector categories and reasons must be lists")

        return self.DetectorResult(
            label=label,
            score=float(payload["score"]),
            risk_score=self._risk_score(payload),
            categories=[str(category) for category in categories],
            reasons=[str(reason) for reason in reasons],
            model=str(payload.get("model", "external-detector")),
        )

    @staticmethod
    def _extract_prompt(arguments: Dict[str, Any]) -> str:
        for key in ("prompt", "input", "query", "text", "command"):
            value = arguments.get(key)
            if isinstance(value, str) and value:
                return value
        return json.dumps(arguments, sort_keys=True, default=str)

    @staticmethod
    def _risk_score(payload: Dict[str, Any]) -> int:
        score = float(payload.get("score", 0))
        if score <= 1:
            return max(0, min(100, round(score * 100)))
        return max(0, min(100, round(score)))


def apply_detector_result(
    scan_result: ScanResult,
    detector_result: Optional[ExternalDetectorClient.DetectorResult],
) -> ScanResult:
    """Merge detector score into a rules scan result."""
    if (
        detector_result is None
        or detector_result.risk_score <= 0
        or detector_result.label == "benign"
        or detector_result.model == "error"
    ):
        return scan_result

    scan_result.scoring_breakdown["detector_score"] = detector_result.risk_score

    if detector_result.risk_score > scan_result.score:
        scan_result.score = detector_result.risk_score

    if detector_result.risk_score >= 70:
        scan_result.level = "THREAT"
        scan_result.action = "BLOCK"
    elif detector_result.risk_score >= 30 and scan_result.score < 70:
        scan_result.level = "SUSPICIOUS"
        scan_result.action = "WARN"

    if detector_result.label != "benign":
        reason = "; ".join(detector_result.reasons) or "External detector match"
        category = (
            detector_result.categories[0]
            if detector_result.categories
            else "external_detector"
        )
        scan_result.matched_rules.append(
            DetectionRule(
                id=f"external-detector-{detector_result.label}",
                severity="critical" if detector_result.risk_score >= 70 else "medium",
                message=f"{detector_result.model}: {reason}",
                pattern="",
                score=detector_result.risk_score,
                category=category,
                owasp=["LLM01", "MCP06"],
            )
        )

    return scan_result
