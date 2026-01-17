"""Tests for intent_monitor - 4D profiling for Claude Code sessions."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'trustworthy-core', 'src'))

from trustworthy_mcp.tools.intent_monitor import (
    IntentProfile,
    monitor_intent,
    get_session_profile,
    clear_session_profile,
    update_profile_stats,
)
from trustworthy_core.rubric import (
    AutonomyLevel,
    EfficacyLevel,
    GoalComplexityLevel,
    GeneralityLevel,
)


class TestIntentProfile:
    """Tests for IntentProfile dataclass."""

    def test_basic_creation(self):
        """Test basic IntentProfile creation."""
        profile = IntentProfile(
            task_description="Test task",
            expected_tools=["read_file", "write_file"],
        )
        assert profile.task_description == "Test task"
        assert profile.expected_tools == ["read_file", "write_file"]

    def test_default_values(self):
        """Test default values."""
        profile = IntentProfile(
            task_description="Test",
            expected_tools=[],
        )
        assert profile.autonomy_level == AutonomyLevel.COLLABORATOR
        assert profile.efficacy_level == EfficacyLevel.OBSERVATION_ONLY
        assert profile.goal_complexity == GoalComplexityLevel.SEQUENTIAL
        assert profile.generality == GeneralityLevel.DOMAIN_SPECIFIC
        assert profile.risk_score == 0.0

    def test_to_dict(self):
        """Test to_dict method."""
        profile = IntentProfile(
            task_description="Test",
            expected_tools=["read_file"],
        )
        result = profile.to_dict()
        assert isinstance(result, dict)
        assert "task_description" in result
        assert "expected_tools" in result
        assert "rubric" in result
        assert "risk_score" in result


class TestMonitorIntent:
    """Tests for monitor_intent function."""

    def setup_method(self):
        """Clear session before each test."""
        clear_session_profile()

    def test_returns_dict(self):
        """monitor_intent should return a dictionary."""
        result = monitor_intent(
            task_description="Test task",
            expected_tools=["read_file"],
        )
        assert isinstance(result, dict)

    def test_contains_required_fields(self):
        """Result should contain required fields."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )
        assert "status" in result
        assert "goal_complexity" in result
        assert "generality" in result
        assert "risk_assessment" in result
        assert "recommended_approvals" in result

    def test_sets_session_profile(self):
        """Should set the session profile."""
        assert get_session_profile() is None

        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )

        profile = get_session_profile()
        assert profile is not None
        assert profile.task_description == "Test"

    def test_autonomy_level_parsing(self):
        """Should parse autonomy level correctly."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
            autonomy_level="consultant",
        )
        profile = get_session_profile()
        assert profile.autonomy_level == AutonomyLevel.CONSULTANT

    def test_operator_autonomy(self):
        """Should handle operator autonomy level."""
        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
            autonomy_level="operator",
        )
        profile = get_session_profile()
        assert profile.autonomy_level == AutonomyLevel.OPERATOR

    def test_observer_autonomy(self):
        """Should handle observer autonomy level."""
        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
            autonomy_level="observer",
        )
        profile = get_session_profile()
        assert profile.autonomy_level == AutonomyLevel.OBSERVER


class TestToolEstimation:
    """Tests for tool-based rubric estimation."""

    def setup_method(self):
        """Clear session before each test."""
        clear_session_profile()

    def test_read_only_tools_low_efficacy(self):
        """Read-only tools should estimate low efficacy."""
        result = monitor_intent(
            task_description="Read files",
            expected_tools=["read_file", "list_directory"],
        )
        # Efficacy should be relatively low
        efficacy_level = result["efficacy"]["level"]
        assert efficacy_level in ["E.0", "E.1", "E.2"]

    def test_execute_command_high_efficacy(self):
        """Execute command should estimate high efficacy."""
        result = monitor_intent(
            task_description="Run commands",
            expected_tools=["execute_command"],
        )
        efficacy_level = result["efficacy"]["level"]
        assert efficacy_level in ["E.3", "E.4", "E.5"]

    def test_high_risk_tools_require_approval(self):
        """High-risk tools should be recommended for approval."""
        result = monitor_intent(
            task_description="Execute things",
            expected_tools=["execute_command", "delete_file", "http_request"],
        )
        approvals = result["recommended_approvals"]
        assert "execute_command" in approvals
        assert "delete_file" in approvals
        assert "http_request" in approvals

    def test_safe_tools_no_approval(self):
        """Safe tools should not require approval."""
        result = monitor_intent(
            task_description="Read files",
            expected_tools=["read_file", "list_directory"],
        )
        approvals = result["recommended_approvals"]
        assert "read_file" not in approvals
        assert "list_directory" not in approvals


class TestRiskAssessment:
    """Tests for risk assessment calculation."""

    def setup_method(self):
        clear_session_profile()

    def test_risk_score_range(self):
        """Risk score should be between 0 and 1."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )
        assert 0.0 <= result["risk_assessment"] <= 1.0

    def test_high_risk_tools_higher_score(self):
        """High-risk tools should result in higher risk score."""
        low_risk = monitor_intent(
            task_description="Read",
            expected_tools=["read_file"],
        )
        clear_session_profile()

        high_risk = monitor_intent(
            task_description="Execute",
            expected_tools=["execute_command", "delete_file"],
        )

        assert high_risk["risk_assessment"] > low_risk["risk_assessment"]


class TestGetSessionProfile:
    """Tests for get_session_profile function."""

    def setup_method(self):
        clear_session_profile()

    def test_returns_none_initially(self):
        """Should return None when no profile set."""
        assert get_session_profile() is None

    def test_returns_profile_after_monitor(self):
        """Should return profile after monitor_intent called."""
        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )
        profile = get_session_profile()
        assert profile is not None
        assert isinstance(profile, IntentProfile)


class TestClearSessionProfile:
    """Tests for clear_session_profile function."""

    def test_clears_existing_profile(self):
        """Should clear existing profile."""
        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )
        assert get_session_profile() is not None

        clear_session_profile()
        assert get_session_profile() is None

    def test_safe_to_clear_when_none(self):
        """Should be safe to clear when no profile exists."""
        clear_session_profile()  # Should not raise
        clear_session_profile()  # Should still not raise


class TestUpdateProfileStats:
    """Tests for update_profile_stats function."""

    def setup_method(self):
        clear_session_profile()
        monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
        )

    def test_records_injection(self):
        """Should record injection detection."""
        profile = get_session_profile()
        initial = profile.detection_stats.detected_injections

        update_profile_stats(detected_injection=True)

        assert profile.detection_stats.detected_injections == initial + 1

    def test_records_sanitization(self):
        """Should record sanitization."""
        profile = get_session_profile()
        initial = profile.detection_stats.sanitized_messages

        update_profile_stats(sanitized=True)

        assert profile.detection_stats.sanitized_messages == initial + 1

    def test_records_block(self):
        """Should record blocked messages."""
        profile = get_session_profile()
        initial = profile.detection_stats.halted_messages

        update_profile_stats(blocked=True)

        assert profile.detection_stats.halted_messages == initial + 1

    def test_records_approval(self):
        """Should record approval decisions."""
        profile = get_session_profile()

        update_profile_stats(approved=True)
        assert profile.detection_stats.approved_requests == 1

        update_profile_stats(approved=False)
        assert profile.detection_stats.denied_requests == 1

    def test_updates_timestamp(self):
        """Should update the updated_at timestamp."""
        profile = get_session_profile()
        assert profile.updated_at is None

        update_profile_stats(detected_injection=True)

        assert profile.updated_at is not None

    def test_no_op_without_profile(self):
        """Should do nothing if no profile exists."""
        clear_session_profile()
        # Should not raise
        update_profile_stats(detected_injection=True)


class TestEdgeCases:
    """Edge case tests."""

    def setup_method(self):
        clear_session_profile()

    def test_empty_task_description(self):
        """Should handle empty task description."""
        result = monitor_intent(
            task_description="",
            expected_tools=["read_file"],
        )
        assert isinstance(result, dict)

    def test_empty_tools_list(self):
        """Should handle empty tools list."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=[],
        )
        assert isinstance(result, dict)
        assert result["expected_tool_count"] == 0

    def test_unknown_autonomy_level(self):
        """Should handle unknown autonomy level."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
            autonomy_level="unknown_level",
        )
        # Should fall back to default
        profile = get_session_profile()
        assert profile.autonomy_level == AutonomyLevel.COLLABORATOR

    def test_case_insensitive_autonomy(self):
        """Should handle case variations in autonomy level."""
        result = monitor_intent(
            task_description="Test",
            expected_tools=["read_file"],
            autonomy_level="CONSULTANT",
        )
        profile = get_session_profile()
        assert profile.autonomy_level == AutonomyLevel.CONSULTANT
