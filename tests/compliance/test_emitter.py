"""Tests for compliance evidence emission."""

import pytest

from prooflayer.compliance import ComplianceEmitter, EvidenceRecord


def _event(category="prompt_injection"):
    return {
        "event_type": "detection",
        "category": category,
        "timestamp": "2026-06-13T00:00:00Z",
        "session_id": "thread-1",
        "decision": "BLOCK",
        "rule_ids": ["rule-1"],
        "event_hash": "abc123",
    }


def test_evidence_record_hashes_event_with_previous_hash():
    first = EvidenceRecord.from_event(
        "nist_ai_rmf",
        "nist-measure-01",
        "detection_event",
        _event(),
    )
    second = EvidenceRecord.from_event(
        "nist_ai_rmf",
        "nist-measure-01",
        "detection_event",
        _event(),
        previous_hash=first.evidence_hash,
    )

    assert first.evidence_hash
    assert second.previous_hash == first.evidence_hash
    assert second.evidence_hash != first.evidence_hash


def test_emitter_rejects_unknown_framework():
    with pytest.raises(ValueError, match="Unsupported compliance framework"):
        ComplianceEmitter(["pci"])


def test_emitter_maps_prompt_injection_to_selected_frameworks():
    records = ComplianceEmitter(["nist_ai_rmf", "soc2"]).emit(_event())

    assert [(record.framework, record.control_id) for record in records] == [
        ("nist_ai_rmf", "nist-measure-01"),
        ("soc2", "soc2-cc7-03"),
    ]
    assert all(record.evidence_type == "detection_event" for record in records)


def test_emitter_maps_tool_abuse_to_multiple_controls():
    records = ComplianceEmitter(["eu_ai_act"]).emit(_event("tool_abuse"))

    assert [record.control_id for record in records] == [
        "eu-ai-act-14-04",
        "eu-ai-act-15-02",
    ]


def test_emitter_maps_eval_reports():
    records = ComplianceEmitter(["hipaa"]).emit(
        {
            "event_type": "eval_report",
            "timestamp": "2026-06-13T00:00:00Z",
            "event_hash": "eval-1",
        }
    )

    assert len(records) == 1
    assert records[0].control_id == "hipaa-164-308-a8"
    assert records[0].evidence_type == "eval_report"


def test_emitter_returns_empty_list_for_unmapped_event():
    records = ComplianceEmitter(["nist_ai_rmf"]).emit(
        {"event_type": "unknown", "category": "unknown"}
    )

    assert records == []
