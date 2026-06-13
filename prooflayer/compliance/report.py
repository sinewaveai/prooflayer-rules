"""Compliance evidence report generation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .evidence import EvidenceRecord


@dataclass
class ComplianceReport:
    """A rendered compliance report and its source evidence records."""

    title: str
    evidence_records: List[EvidenceRecord]
    markdown: str


class ComplianceReportGenerator:
    """Generate Markdown and optional PDF compliance evidence reports."""

    def build(
        self,
        evidence_records: Iterable[EvidenceRecord],
        title: str = "ProofLayer Compliance Evidence Report",
    ) -> ComplianceReport:
        """Build a Markdown compliance report from evidence records."""
        records = list(evidence_records)
        markdown = self.to_markdown(records, title)
        return ComplianceReport(
            title=title,
            evidence_records=records,
            markdown=markdown,
        )

    def to_markdown(
        self,
        evidence_records: Iterable[EvidenceRecord],
        title: str = "ProofLayer Compliance Evidence Report",
        output_path: Optional[Path] = None,
    ) -> str:
        """Render evidence records as Markdown and optionally write to disk."""
        records = list(evidence_records)
        grouped = self._group_by_framework(records)
        lines = [
            f"# {title}",
            "",
            f"Total evidence records: {len(records)}",
            "",
        ]
        for framework, framework_records in grouped.items():
            lines.extend([f"## {framework}", ""])
            for record in framework_records:
                lines.extend(
                    [
                        f"### {record.control_id}",
                        "",
                        f"- Evidence type: {record.evidence_type}",
                        f"- Event ID: {record.event_id}",
                        f"- Evidence hash: {record.evidence_hash}",
                        f"- Previous hash: {record.previous_hash or ''}",
                        "",
                    ]
                )
        body = "\n".join(lines).rstrip() + "\n"
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(body, encoding="utf-8")
        return body

    def to_pdf(self, markdown: str, output_path: Path) -> None:
        """Render Markdown text to PDF using WeasyPrint when installed."""
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError(
                "PDF generation requires the compliance extra: "
                "pip install prooflayer-rules[compliance]"
            ) from exc

        html = "<pre>" + self._escape_html(markdown) + "</pre>"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html).write_pdf(str(output_path))

    def _group_by_framework(
        self,
        evidence_records: Iterable[EvidenceRecord],
    ) -> Dict[str, List[EvidenceRecord]]:
        grouped: Dict[str, List[EvidenceRecord]] = {}
        for record in evidence_records:
            grouped.setdefault(record.framework, []).append(record)
        return grouped

    def _escape_html(self, text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
