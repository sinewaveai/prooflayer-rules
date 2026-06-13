"""GARAK Docker runner and result parser."""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .report import EvalFinding


class GarakRunner:
    """Run GARAK probes against an OpenAI-compatible LangGraph endpoint."""

    def __init__(
        self,
        image: str = "leondz/garak:0.10.0",
        timeout_seconds: int = 900,
    ) -> None:
        """Initialize the Docker-backed GARAK runner."""
        self.image = image
        self.timeout_seconds = timeout_seconds

    def build_command(
        self,
        endpoint_url: str,
        output_dir: Path,
        probes: Optional[Iterable[str]] = None,
    ) -> List[str]:
        """Build the Docker command used to invoke GARAK."""
        probe_args: List[str] = []
        if probes:
            probe_args = ["--probes", ",".join(probes)]
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{output_dir.resolve()}:/reports",
            "-e",
            f"OPENAI_API_BASE={endpoint_url}",
            self.image,
            "garak",
            "--model_type",
            "openai",
            "--model_name",
            "prooflayer-langgraph",
            "--report_prefix",
            "/reports/garak",
            *probe_args,
        ]

    def run(
        self,
        endpoint_url: str,
        output_dir: Path,
        probes: Optional[Iterable[str]] = None,
    ) -> List[EvalFinding]:
        """Run GARAK in Docker and parse the generated JSON report."""
        output_dir.mkdir(parents=True, exist_ok=True)
        command = self.build_command(endpoint_url, output_dir, probes)
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        return self.parse_report(output_dir)

    def parse_report(self, output_dir: Path) -> List[EvalFinding]:
        """Parse GARAK JSON output files into normalized findings."""
        report_files = sorted(output_dir.glob("garak*.json"))
        findings: List[EvalFinding] = []
        for report_file in report_files:
            data = json.loads(report_file.read_text(encoding="utf-8"))
            findings.extend(self._findings_from_payload(data))
        return findings

    def _findings_from_payload(self, payload: Any) -> List[EvalFinding]:
        if isinstance(payload, dict) and "findings" in payload:
            records = payload["findings"]
        elif isinstance(payload, dict) and "results" in payload:
            records = payload["results"]
        elif isinstance(payload, list):
            records = payload
        else:
            records = [payload]

        findings: List[EvalFinding] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            passed = bool(record.get("passed", not record.get("failure", False)))
            severity = str(record.get("severity", "high" if not passed else "low"))
            findings.append(
                EvalFinding(
                    id=str(record.get("id", record.get("probe", f"garak-{index}"))),
                    source="garak",
                    category=str(record.get("category", record.get("probe", "garak"))),
                    severity=severity,
                    prompt=str(record.get("prompt", "")),
                    outcome=str(record.get("outcome", record.get("status", ""))),
                    passed=passed,
                    details={k: v for k, v in record.items() if k != "prompt"},
                )
            )
        return findings
