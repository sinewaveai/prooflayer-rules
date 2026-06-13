"""Tests for scope drift detection."""

from prooflayer.detection.scope_drift import ScopeDriftDetector


def test_scope_drift_detector_flags_scope_bypass_language():
    detector = ScopeDriftDetector()

    findings = detector.detect("I can ignore the scope and do anything you want.")

    assert [finding.rule_id for finding in findings] == [
        "scope-drift-ignore-scope",
        "scope-drift-unrestricted-help",
    ]


def test_scope_drift_detector_allows_normal_output():
    detector = ScopeDriftDetector()

    assert detector.detect("ProofLayer secures LangGraph workflows.") == []
