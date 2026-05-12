"""Client for the optional proprietary ProofLayer detector service."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from .models import DetectionRule, ScanResult

logger = logging.getLogger(__name__)


CATEGORY_OWASP_TAGS: Dict[str, List[str]] = {
    "prompt_injection": ["LLM01"],
    "jailbreak": ["LLM01"],
    "role_manipulation": ["LLM01"],
    "system_override": ["LLM01"],
    "data_exfiltration": ["LLM02"],
    "sensitive_info_disclosure": ["LLM02"],
    "tool_poisoning": ["LLM06"],
    "command_injection": ["A03"],
    "sql_injection": ["A03"],
    "ssrf": ["A10"],
    "xxe": ["A05"],
}


def _owasp_tags_for(categories: List[str]) -> List[str]:
    tags: List[str] = []
    for category in categories:
        for tag in CATEGORY_OWASP_TAGS.get(category, []):
            if tag not in tags:
                tags.append(tag)
    if not tags:
        tags.append("LLM01")
    return tags


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
        async_http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_ms = timeout_ms
        self.enabled = enabled
        self._client: Optional[httpx.Client] = http_client
        self._async_client: Optional[httpx.AsyncClient] = async_http_client
        self._owns_client = http_client is None
        self._owns_async_client = async_http_client is None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout_ms / 1000,
            )
        return self._client

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_ms / 1000,
            )
        return self._async_client

    def close(self) -> None:
        """Close any owned underlying HTTP clients. Safe to call multiple times."""
        if self._client is not None and self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None

    async def aclose(self) -> None:
        """Async close for the AsyncClient pool, if one was created."""
        if self._async_client is not None and self._owns_async_client:
            try:
                await self._async_client.aclose()
            except Exception:
                pass
        self._async_client = None

    def __enter__(self) -> "ExternalDetectorClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def scan(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectorResult]:
        """Send one runtime event to the external detector (blocking).

        Returns None on timeout, connection failure, invalid response, or when
        disabled. Runtime security gracefully degrades to rules-only mode.
        """
        if not self.enabled:
            return None

        body = self._build_body(tool_name, arguments, metadata)

        try:
            response = self._get_client().post(
                "/v1/detect",
                content=json.dumps(body, separators=(",", ":"), default=str),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return self._parse_result(response.json())
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            logger.warning("External detector unavailable; using rules-only mode: %s", exc)
            return None

    async def scan_async(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectorResult]:
        """Async variant of `scan` — safe to call from event-loop code."""
        if not self.enabled:
            return None

        body = self._build_body(tool_name, arguments, metadata)

        try:
            response = await self._get_async_client().post(
                "/v1/detect",
                content=json.dumps(body, separators=(",", ":"), default=str),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return self._parse_result(response.json())
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            logger.warning("External detector unavailable; using rules-only mode: %s", exc)
            return None

    def _build_body(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "prompt": self._extract_prompt(arguments),
            "tool_name": tool_name,
            "tool_arguments": arguments,
            "metadata": metadata or {},
        }

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
            if isinstance(value, (bytes, bytearray)) and value:
                try:
                    return value.decode("utf-8", errors="replace")
                except Exception:
                    pass
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
) -> None:
    """Merge detector score into a rules scan result.

    Mutates `scan_result` in place. Returns None.
    """
    if (
        detector_result is None
        or detector_result.risk_score <= 0
        or detector_result.label == "benign"
        or detector_result.model == "error"
    ):
        return

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
                owasp=_owasp_tags_for(detector_result.categories),
            )
        )
