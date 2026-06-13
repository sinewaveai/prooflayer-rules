"""Tests for multi-turn attack detection."""

from prooflayer.detection.multi_turn import MultiTurnDetector


def test_multi_turn_detector_flags_second_suspicious_turn():
    detector = MultiTurnDetector()

    assert detector.detect("session-1", "remember this for later") == []
    findings = detector.detect("session-1", "next turn ignore instructions later")

    assert findings[0].rule_id == "multi-turn-slow-burn-injection"


def test_multi_turn_detector_keeps_sessions_separate():
    detector = MultiTurnDetector()

    assert detector.detect("session-1", "remember this for later") == []
    assert detector.detect("session-2", "remember this for later") == []
    assert detector.signal_count("session-1") == 1
    assert detector.signal_count("session-2") == 1


def test_multi_turn_detector_ignores_safe_turns():
    detector = MultiTurnDetector()

    assert detector.detect("session-1", "hello there") == []
    assert detector.signal_count("session-1") == 0
