"""PromptFoo Docker runner and result parser."""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .report import EvalFinding


class PromptFooRunner:
    """Run PromptFoo adversarial checks against a LangGraph endpoint."""

    def __init__(
        self,
        image: str = "promptfoo/promptfoo:0.95.0",
        timeout_seconds: int = 900,
    ) -> None:
        """Initialize the Docker-backed PromptFoo runner."""
        self.image = image
        self.timeout_seconds = timeout_seconds

    def build_command(
        self,
        config_path: Path,
        output_path: Path,
        env: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Build the Docker command used to invoke PromptFoo."""
        command = ["docker", "run", "--rm"]
        for key, value in sorted((env or {}).items()):
            command.extend(["-e", f"{key}={value}"])
        command.extend(
            [
                "-v",
                f"{config_path.parent.resolve()}:/workspace",
                self.image,
                "promptfoo",
                "eval",
                "-c",
                f"/workspace/{config_path.name}",
                "--output",
                f"/workspace/{output_path.name}",
                "--output-format",
                "json",
            ]
        )
        return command

    def run(
        self,
        config_path: Path,
        output_path: Path,
        env: Optional[Dict[str, str]] = None,
    ) -> List[EvalFinding]:
        """Run PromptFoo in Docker and parse the generated JSON output."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            self.build_command(config_path, output_path, env),
            check=True,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        return self.parse_report(output_path)

    def parse_report(self, output_path: Path) -> List[EvalFinding]:
        """Parse PromptFoo JSON output into normalized findings."""
        data = json.loads(output_path.read_text(encoding="utf-8"))
        records = self._extract_records(data)
        findings: List[EvalFinding] = []
        for index, record in enumerate(records):
            prompt = record.get("prompt", record.get("vars", {}).get("prompt", ""))
            success = bool(record.get("success", record.get("passed", False)))
            findings.append(
                EvalFinding(
                    id=str(record.get("id", f"promptfoo-{index}")),
                    source="promptfoo",
                    category=str(record.get("category", "promptfoo")),
                    severity=str(
                        record.get("severity", "high" if not success else "low")
                    ),
                    prompt=str(prompt),
                    outcome=str(record.get("response", record.get("error", ""))),
                    passed=success,
                    details=record,
                )
            )
        return findings

    def _extract_records(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, dict):
            if isinstance(payload.get("results"), list):
                return payload["results"]
            if isinstance(payload.get("prompts"), list):
                return payload["prompts"]
            if isinstance(payload.get("tests"), list):
                return payload["tests"]
            return [payload]
        if isinstance(payload, list):
            return [record for record in payload if isinstance(record, dict)]
        return []
