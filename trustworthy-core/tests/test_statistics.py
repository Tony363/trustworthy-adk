"""Tests for statistics.py - Detection rate tracking and metrics."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from trustworthy_core.statistics import DetectionStatistics


class TestDetectionStatistics:
    """Tests for DetectionStatistics class."""

    def test_initial_values(self):
        """Initial values should all be zero."""
        stats = DetectionStatistics()
        assert stats.total_messages == 0
        assert stats.detected_injections == 0
        assert stats.sanitized_messages == 0
        assert stats.halted_messages == 0
        assert stats.approved_requests == 0
        assert stats.denied_requests == 0

    def test_record_message(self):
        """record_message should increment total_messages."""
        stats = DetectionStatistics()
        stats.record_message()
        assert stats.total_messages == 1
        stats.record_message()
        stats.record_message()
        assert stats.total_messages == 3

    def test_record_detection(self):
        """record_detection should increment detected_injections."""
        stats = DetectionStatistics()
        stats.record_detection()
        assert stats.detected_injections == 1
        stats.record_detection()
        assert stats.detected_injections == 2

    def test_record_sanitization(self):
        """record_sanitization should increment sanitized_messages."""
        stats = DetectionStatistics()
        stats.record_sanitization()
        assert stats.sanitized_messages == 1

    def test_record_halt(self):
        """record_halt should increment halted_messages."""
        stats = DetectionStatistics()
        stats.record_halt()
        assert stats.halted_messages == 1

    def test_record_approval_approved(self):
        """record_approval(True) should increment approved_requests."""
        stats = DetectionStatistics()
        stats.record_approval(approved=True)
        assert stats.approved_requests == 1
        assert stats.denied_requests == 0

    def test_record_approval_denied(self):
        """record_approval(False) should increment denied_requests."""
        stats = DetectionStatistics()
        stats.record_approval(approved=False)
        assert stats.approved_requests == 0
        assert stats.denied_requests == 1


class TestDetectionRate:
    """Tests for detection_rate property."""

    def test_detection_rate_zero_messages(self):
        """Detection rate should be 0 with no messages."""
        stats = DetectionStatistics()
        assert stats.detection_rate == 0.0

    def test_detection_rate_no_detections(self):
        """Detection rate should be 0 with no detections."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_message()
        assert stats.detection_rate == 0.0

    def test_detection_rate_all_detected(self):
        """Detection rate should be 1.0 when all messages have detections."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_detection()
        stats.record_message()
        stats.record_detection()
        assert stats.detection_rate == 1.0

    def test_detection_rate_partial(self):
        """Detection rate should reflect partial detections."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_detection()
        stats.record_message()
        # 1 detection out of 2 messages = 0.5
        assert stats.detection_rate == 0.5

    def test_detection_rate_range(self):
        """Detection rate should always be between 0.0 and 1.0."""
        stats = DetectionStatistics()
        for _ in range(100):
            stats.record_message()
        for _ in range(50):
            stats.record_detection()
        assert 0.0 <= stats.detection_rate <= 1.0
        assert stats.detection_rate == 0.5


class TestSanitizationRate:
    """Tests for sanitization_rate property."""

    def test_sanitization_rate_zero_messages(self):
        """Sanitization rate should be 0 with no messages."""
        stats = DetectionStatistics()
        assert stats.sanitization_rate == 0.0

    def test_sanitization_rate_calculation(self):
        """Sanitization rate should calculate correctly."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_message()
        stats.record_sanitization()
        # 1 sanitization out of 2 messages = 0.5
        assert stats.sanitization_rate == 0.5


class TestHaltRate:
    """Tests for halt_rate property."""

    def test_halt_rate_zero_messages(self):
        """Halt rate should be 0 with no messages."""
        stats = DetectionStatistics()
        assert stats.halt_rate == 0.0

    def test_halt_rate_calculation(self):
        """Halt rate should calculate correctly."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_message()
        stats.record_message()
        stats.record_message()
        stats.record_halt()
        # 1 halt out of 4 messages = 0.25
        assert stats.halt_rate == 0.25


class TestApprovalRate:
    """Tests for approval_rate property."""

    def test_approval_rate_no_requests(self):
        """Approval rate should be 1.0 with no requests (default safe)."""
        stats = DetectionStatistics()
        assert stats.approval_rate == 1.0

    def test_approval_rate_all_approved(self):
        """Approval rate should be 1.0 when all approved."""
        stats = DetectionStatistics()
        stats.record_approval(True)
        stats.record_approval(True)
        assert stats.approval_rate == 1.0

    def test_approval_rate_all_denied(self):
        """Approval rate should be 0.0 when all denied."""
        stats = DetectionStatistics()
        stats.record_approval(False)
        stats.record_approval(False)
        assert stats.approval_rate == 0.0

    def test_approval_rate_mixed(self):
        """Approval rate should reflect mix of approved/denied."""
        stats = DetectionStatistics()
        stats.record_approval(True)
        stats.record_approval(True)
        stats.record_approval(False)
        # 2 approved out of 3 total
        assert abs(stats.approval_rate - 2/3) < 0.001


class TestToDict:
    """Tests for to_dict() method."""

    def test_to_dict_returns_dict(self):
        """to_dict should return a dictionary."""
        stats = DetectionStatistics()
        result = stats.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_contains_nested_structure(self):
        """to_dict should contain counts, rates, and timestamps."""
        stats = DetectionStatistics()
        result = stats.to_dict()
        assert "counts" in result
        assert "rates" in result
        assert "timestamps" in result

    def test_to_dict_contains_all_count_fields(self):
        """to_dict should contain all counter fields in counts."""
        stats = DetectionStatistics()
        result = stats.to_dict()
        counts = result["counts"]
        assert "total_messages" in counts
        assert "detected_injections" in counts
        assert "sanitized_messages" in counts
        assert "halted_messages" in counts
        assert "approved_requests" in counts
        assert "denied_requests" in counts

    def test_to_dict_contains_rates(self):
        """to_dict should contain all rate fields in rates."""
        stats = DetectionStatistics()
        stats.record_message()  # Need at least one message for rates
        result = stats.to_dict()
        rates = result["rates"]
        assert "detection_rate" in rates
        assert "sanitization_rate" in rates
        assert "halt_rate" in rates
        assert "approval_rate" in rates

    def test_to_dict_values_match(self):
        """to_dict values should match actual values."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_message()
        stats.record_detection()
        stats.record_sanitization()

        result = stats.to_dict()
        assert result["counts"]["total_messages"] == 2
        assert result["counts"]["detected_injections"] == 1
        assert result["counts"]["sanitized_messages"] == 1
        assert result["rates"]["detection_rate"] == 0.5


class TestReset:
    """Tests for reset() method."""

    def test_reset_clears_counters(self):
        """reset should clear all counters."""
        stats = DetectionStatistics()
        stats.record_message()
        stats.record_detection()
        stats.record_sanitization()
        stats.record_halt()
        stats.record_approval(True)

        stats.reset()

        assert stats.total_messages == 0
        assert stats.detected_injections == 0
        assert stats.sanitized_messages == 0
        assert stats.halted_messages == 0
        assert stats.approved_requests == 0
        assert stats.denied_requests == 0


class TestEdgeCases:
    """Edge case tests."""

    def test_many_operations(self):
        """Should handle many operations without overflow."""
        stats = DetectionStatistics()
        for _ in range(10000):
            stats.record_message()
            if _ % 10 == 0:
                stats.record_detection()

        assert stats.total_messages == 10000
        assert stats.detected_injections == 1000
        assert stats.detection_rate == 0.1

    def test_rates_precision(self):
        """Rates should have reasonable precision."""
        stats = DetectionStatistics()
        for _ in range(3):
            stats.record_message()
        stats.record_detection()

        # 1/3 should be approximately 0.333...
        assert abs(stats.detection_rate - 1/3) < 0.001
