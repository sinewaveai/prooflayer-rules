"""Tests for ProofLayer audit logging."""

import io
import json

from prooflayer.audit import AuditEvent, AuditLogger, chain_hash, to_siem_event


def test_chain_hash_is_deterministic_and_links_previous_hash():
    payload = {"rule_id": "direct-ignore-previous", "decision": "BLOCK"}

    first = chain_hash(payload)
    second = chain_hash(payload)
    linked = chain_hash(payload, previous_hash=first)

    assert first == second
    assert linked != first


def test_audit_logger_writes_human_readable_stdout():
    stream = io.StringIO()
    logger = AuditLogger(stream=stream)

    event = logger.log(
        AuditEvent(
            session_id="session-1",
            rule_id="direct-ignore-previous",
            severity="critical",
            decision="BLOCK",
            evidence_snippet="ignore previous instructions",
        )
    )

    output = stream.getvalue()
    assert "BLOCK direct-ignore-previous" in output
    assert event.event_hash in output


def test_audit_logger_writes_jsonl_file(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(emit_to=[f"logfile:{audit_path}"])

    event = logger.log(
        AuditEvent(
            session_id="session-1",
            rule_id="direct-ignore-previous",
            severity="critical",
            decision="BLOCK",
            evidence_snippet="ignore previous instructions",
        )
    )

    rows = audit_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(rows[0])
    assert payload["event_hash"] == event.event_hash
    assert payload["previous_hash"] is None


def test_audit_logger_links_consecutive_events(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(emit_to=[f"logfile:{audit_path}"])

    first = logger.log(
        AuditEvent(
            session_id="session-1",
            rule_id="direct-ignore-previous",
            severity="critical",
            decision="WARN",
            evidence_snippet="ignore previous instructions",
        )
    )
    second = logger.log(
        AuditEvent(
            session_id="session-1",
            rule_id="direct-disregard-system",
            severity="critical",
            decision="BLOCK",
            evidence_snippet="disregard system prompt",
        )
    )

    assert second.previous_hash == first.event_hash
    assert logger.previous_hash == second.event_hash


def test_audit_logger_writes_siem_json_to_stream():
    stream = io.StringIO()
    logger = AuditLogger(emit_to=["siem"], stream=stream)

    logger.log(
        AuditEvent(
            session_id="session-1",
            rule_id="direct-ignore-previous",
            severity="critical",
            decision="BLOCK",
            evidence_snippet="ignore previous instructions",
        )
    )

    payload = json.loads(stream.getvalue())
    assert payload["sourcetype"] == "prooflayer:audit"
    assert payload["event"]["rule_id"] == "direct-ignore-previous"


def test_to_siem_event_wraps_audit_payload():
    event = {"timestamp": "2026-01-01T00:00:00Z", "rule_id": "r1"}

    payload = to_siem_event(event)

    assert payload["time"] == "2026-01-01T00:00:00Z"
    assert payload["event"] == event
