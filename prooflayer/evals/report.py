"""JSON and Markdown report generation for adversarial eval findings."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class EvalFinding:
    """A normalized finding from GARAK, PromptFoo, or ProofLayer probes."""

    id: str
    source: str
    category: str
    severity: str
    prompt: str
    outcome: str
    passed: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalReport:
    """A normalized adversarial eval report."""

    target_name: str
    findings: List[EvalFinding]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def failed_count(self) -> int:
        """Return the number of findings that indicate a failed protection."""
        return len([finding for finding in self.findings if not finding.passed])

    @property
    def passed_count(self) -> int:
        """Return the number of findings that passed."""
        return len([finding for finding in self.findings if finding.passed])

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable report dictionary."""
        return {
            "target_name": self.target_name,
            "generated_at": self.generated_at,
            "summary": {
                "total": len(self.findings),
                "passed": self.passed_count,
                "failed": self.failed_count,
            },
            "findings": [asdict(finding) for finding in self.findings],
        }


class ReportGenerator:
    """Render adversarial eval reports as JSON and Markdown."""

    def build(
        self,
        target_name: str,
        findings: Iterable[EvalFinding],
    ) -> EvalReport:
        """Build a normalized eval report from findings."""
        return EvalReport(target_name=target_name, findings=list(findings))

    def to_json(self, report: EvalReport, output_path: Optional[Path] = None) -> str:
        """Render a report to JSON and optionally write it to disk."""
        body = json.dumps(report.to_dict(), indent=2, sort_keys=True)
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(body + "\n", encoding="utf-8")
        return body

    def to_markdown(
        self,
        report: EvalReport,
        output_path: Optional[Path] = None,
    ) -> str:
        """Render a report to Markdown and optionally write it to disk."""
        lines = [
            f"# ProofLayer Adversarial Eval Report: {report.target_name}",
            "",
            f"Generated: {report.generated_at}",
            "",
            "## Summary",
            "",
            f"- Total probes: {len(report.findings)}",
            f"- Passed: {report.passed_count}",
            f"- Failed: {report.failed_count}",
            "",
            "## Findings",
            "",
        ]
        for finding in report.findings:
            status = "PASS" if finding.passed else "FAIL"
            lines.extend(
                [
                    f"### {finding.id} - {status}",
                    "",
                    f"- Source: {finding.source}",
                    f"- Category: {finding.category}",
                    f"- Severity: {finding.severity}",
                    f"- Outcome: {finding.outcome}",
                    "",
                ]
            )
        body = "\n".join(lines).rstrip() + "\n"
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(body, encoding="utf-8")
        return body
