"""Tests for security profiler and visualization."""

import pytest
from datetime import datetime, timedelta

from trustworthy_mcp.audit.logger import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    SecurityProfile,
)
from trustworthy_mcp.resources.profiler import (
    SecurityProfileResource,
    RadarChartData,
)


class TestSecurityProfile:
    """Test SecurityProfile metrics calculation."""

    def test_empty_profile(self):
        """Should handle empty profile correctly."""
        now = datetime.utcnow()
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
        )

        assert profile.autonomy_score == 0.0
        assert profile.risk_exposure_score == 0.0
        assert profile.approval_compliance_score == 1.0  # No denials = compliant
        assert profile.defense_effectiveness_score == 1.0  # No attacks = effective

    def test_autonomy_score_calculation(self):
        """Should calculate autonomy score based on tier distribution."""
        now = datetime.utcnow()

        # All safe operations = low autonomy
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=10,
            tier_1_calls=0,
            tier_2_calls=0,
        )
        assert profile.autonomy_score < 0.2

        # Mix of operations
        profile2 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=5,
            tier_1_calls=3,
            tier_2_calls=2,
        )
        assert 0.2 < profile2.autonomy_score < 0.8

        # All high-risk = high autonomy
        profile3 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=0,
            tier_1_calls=0,
            tier_2_calls=10,
        )
        assert profile3.autonomy_score == 1.0

    def test_risk_exposure_score(self):
        """Should calculate risk exposure based on security events."""
        now = datetime.utcnow()

        # No risky events
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=10,
            injection_attempts=0,
            policy_violations=0,
        )
        assert profile.risk_exposure_score == 0.0

        # Some risky events
        profile2 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=8,
            injection_attempts=1,
            policy_violations=1,
        )
        assert profile2.risk_exposure_score > 0.0

    def test_approval_compliance_score(self):
        """Should calculate compliance based on approval outcomes."""
        now = datetime.utcnow()

        # All approved
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            approvals_granted=5,
            approvals_denied=0,
        )
        assert profile.approval_compliance_score == 1.0

        # All denied
        profile2 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            approvals_granted=0,
            approvals_denied=5,
        )
        assert profile2.approval_compliance_score == 0.0

        # Mixed
        profile3 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            approvals_granted=3,
            approvals_denied=2,
        )
        assert profile3.approval_compliance_score == 0.6

    def test_defense_effectiveness_score(self):
        """Should calculate defense effectiveness."""
        now = datetime.utcnow()

        # All blocked
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            injection_attempts=10,
            injection_blocked=10,
        )
        assert profile.defense_effectiveness_score == 1.0

        # None blocked
        profile2 = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            injection_attempts=10,
            injection_blocked=0,
        )
        assert profile2.defense_effectiveness_score == 0.0

    def test_to_dict(self):
        """Should serialize to dictionary correctly."""
        now = datetime.utcnow()
        profile = SecurityProfile(
            window_start=now - timedelta(hours=1),
            window_end=now,
            tier_0_calls=5,
            tier_1_calls=3,
            tier_2_calls=2,
            injection_attempts=1,
            injection_blocked=1,
        )

        data = profile.to_dict()

        assert "window_start" in data
        assert "window_end" in data
        assert "tool_usage" in data
        assert "security_events" in data
        assert "scores" in data
        assert data["tool_usage"]["total"] == 10


class TestAuditLoggerProfiling:
    """Test AuditLogger profiling capabilities."""

    def test_get_security_profile(self):
        """Should generate profile from audit events."""
        logger = AuditLogger()

        # Log some events
        logger.log_tool_call("read_file", {"path": "test.txt"}, risk_tier=0)
        logger.log_tool_call("write_file", {"path": "out.txt"}, risk_tier=1)
        logger.log_tool_call("execute_command", {"command": "ls"}, risk_tier=2)
        logger.log_injection_detected("write_file", {"risk": 0.9}, blocked=True)

        profile = logger.get_security_profile(window_minutes=60)

        assert profile.tier_0_calls == 1
        assert profile.tier_1_calls == 1
        assert profile.tier_2_calls == 1
        assert profile.injection_attempts == 1
        assert profile.injection_blocked == 1

    def test_profile_window_filtering(self):
        """Should filter events by time window."""
        logger = AuditLogger()

        # Log event
        logger.log_tool_call("read_file", {"path": "test.txt"}, risk_tier=0)

        # Get profile with short window
        profile = logger.get_security_profile(window_minutes=60)
        assert profile.tier_0_calls == 1

        # Events within window should be counted
        profile2 = logger.get_security_profile(window_minutes=1)
        assert profile2.tier_0_calls == 1

    def test_get_profile_summary(self):
        """Should generate human-readable summary."""
        logger = AuditLogger()
        logger.log_tool_call("read_file", {}, risk_tier=0)
        logger.log_tool_call("execute_command", {}, risk_tier=2)

        summary = logger.get_profile_summary(window_minutes=60)

        assert "Security Profile" in summary
        assert "Tool Usage" in summary
        assert "Safe (Tier 0): 1" in summary
        assert "High-Risk (Tier 2): 1" in summary
        assert "Scores" in summary


class TestRadarChartData:
    """Test radar chart data generation."""

    def test_basic_radar_data(self):
        """Should create radar chart data."""
        chart = RadarChartData(
            labels=["A", "B", "C", "D"],
            values=[0.5, 0.8, 0.3, 1.0],
        )

        assert len(chart.labels) == 4
        assert len(chart.values) == 4
        assert chart.max_value == 1.0

    def test_to_dict(self):
        """Should serialize to dictionary."""
        chart = RadarChartData(
            labels=["A", "B"],
            values=[0.5, 0.8],
            title="Test Chart",
        )

        data = chart.to_dict()

        assert data["labels"] == ["A", "B"]
        assert data["values"] == [0.5, 0.8]
        assert data["title"] == "Test Chart"

    def test_to_svg(self):
        """Should generate SVG chart."""
        chart = RadarChartData(
            labels=["Caution", "Safety", "Compliance", "Defense"],
            values=[0.7, 0.8, 1.0, 0.9],
            title="Security Profile",
        )

        svg = chart.to_svg(size=400)

        assert svg.startswith("<svg")
        assert "Security Profile" in svg
        assert "polygon" in svg
        assert "</svg>" in svg

    def test_empty_chart(self):
        """Should handle empty data."""
        chart = RadarChartData(
            labels=[],
            values=[],
        )

        svg = chart.to_svg()

        assert "<svg" in svg
        assert "No data" in svg


class TestSecurityProfileResource:
    """Test MCP resource for security profile."""

    def test_get_profile_json(self):
        """Should return profile as JSON."""
        logger = AuditLogger()
        logger.log_tool_call("read_file", {}, risk_tier=0)

        resource = SecurityProfileResource(logger)
        json_str = resource.get_profile_json()

        assert "tool_usage" in json_str
        assert "scores" in json_str

    def test_get_radar_chart_data(self):
        """Should generate radar chart data."""
        logger = AuditLogger()
        logger.log_tool_call("read_file", {}, risk_tier=0)
        logger.log_tool_call("execute_command", {}, risk_tier=2)

        resource = SecurityProfileResource(logger)
        chart_data = resource.get_radar_chart_data()

        assert len(chart_data.labels) == 4
        assert "Caution" in chart_data.labels
        assert "Safety" in chart_data.labels
        assert "Compliance" in chart_data.labels
        assert "Defense" in chart_data.labels

    def test_get_radar_chart_svg(self):
        """Should generate SVG visualization."""
        logger = AuditLogger()
        resource = SecurityProfileResource(logger)

        svg = resource.get_radar_chart_svg()

        assert "<svg" in svg
        assert "</svg>" in svg

    def test_get_summary(self):
        """Should generate text summary."""
        logger = AuditLogger()
        resource = SecurityProfileResource(logger)

        summary = resource.get_summary()

        assert "Security Profile" in summary
        assert "Scores" in summary

    def test_get_all_formats(self):
        """Should return all formats."""
        logger = AuditLogger()
        resource = SecurityProfileResource(logger)

        all_formats = resource.get_all_formats()

        assert "json" in all_formats
        assert "svg" in all_formats
        assert "text" in all_formats
        assert "radar_data" in all_formats
