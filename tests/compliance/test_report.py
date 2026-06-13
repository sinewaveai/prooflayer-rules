"""Tests for compliance report generation."""

import builtins

import pytest

from prooflayer.compliance import (
    ComplianceEmitter,
    ComplianceReport,
    ComplianceReportGenerator,
)


def test_compliance_report_generator_builds_markdown_report(tmp_path):
    records = ComplianceEmitter(["nist_ai_rmf"]).emit(
        {
            "event_type": "detection",
            "category": "prompt_injection",
            "timestamp": "2026-06-13T00:00:00Z",
            "event_hash": "event-1",
        }
    )
    generator = ComplianceReportGenerator()

    report = generator.build(records)
    markdown = generator.to_markdown(records, output_path=tmp_path / "compliance.md")

    assert isinstance(report, ComplianceReport)
    assert "ProofLayer Compliance Evidence Report" in report.markdown
    assert "nist-measure-01" in markdown
    assert (tmp_path / "compliance.md").exists()


def test_compliance_report_generator_pdf_requires_optional_dependency(
    monkeypatch, tmp_path
):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(RuntimeError, match="prooflayer-rules\\[compliance\\]"):
        ComplianceReportGenerator().to_pdf("hello", tmp_path / "report.pdf")
