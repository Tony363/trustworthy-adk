"""Tests for tool registry and risk classification."""

import pytest

from trustworthy_mcp.tools.registry import ToolRegistry, ToolPolicy, RiskTier


class TestRiskTier:
    """Test risk tier enum."""

    def test_tier_ordering(self):
        """Risk tiers should be ordered from safe to high-risk."""
        assert RiskTier.SAFE < RiskTier.LIMITED < RiskTier.HIGH_RISK
        assert RiskTier.SAFE == 0
        assert RiskTier.LIMITED == 1
        assert RiskTier.HIGH_RISK == 2


class TestToolPolicy:
    """Test tool policy configuration."""

    def test_high_risk_auto_approval(self):
        """High-risk tools should automatically require approval."""
        policy = ToolPolicy(
            name="dangerous_tool",
            risk_tier=RiskTier.HIGH_RISK,
        )
        assert policy.approval_required is True
        assert policy.side_effects is True

    def test_safe_tool_no_auto_approval(self):
        """Safe tools should not auto-require approval."""
        policy = ToolPolicy(
            name="safe_tool",
            risk_tier=RiskTier.SAFE,
        )
        assert policy.approval_required is False
        assert policy.side_effects is False


class TestToolRegistry:
    """Test tool registry functionality."""

    def test_default_tools_registered(self):
        """Registry should have default tools registered."""
        registry = ToolRegistry()
        tools = registry.list_tools()

        assert "read_file" in tools
        assert "write_file" in tools
        assert "execute_command" in tools
        assert "http_request" in tools

    def test_get_risk_tier_known_tool(self):
        """Should return correct tier for known tools."""
        registry = ToolRegistry()

        assert registry.get_risk_tier("read_file") == RiskTier.SAFE
        assert registry.get_risk_tier("write_file") == RiskTier.LIMITED
        assert registry.get_risk_tier("execute_command") == RiskTier.HIGH_RISK

    def test_get_risk_tier_unknown_tool(self):
        """Unknown tools should default to HIGH_RISK."""
        registry = ToolRegistry()
        assert registry.get_risk_tier("unknown_tool") == RiskTier.HIGH_RISK

    def test_requires_approval(self):
        """Should correctly identify tools requiring approval."""
        registry = ToolRegistry()

        assert registry.requires_approval("read_file") is False
        assert registry.requires_approval("execute_command") is True
        assert registry.requires_approval("delete_file") is True
        # Unknown tools require approval
        assert registry.requires_approval("unknown") is True

    def test_list_by_tier(self):
        """Should list tools by tier correctly."""
        registry = ToolRegistry()

        safe_tools = registry.list_by_tier(RiskTier.SAFE)
        high_risk_tools = registry.list_by_tier(RiskTier.HIGH_RISK)

        safe_names = [t.name for t in safe_tools]
        high_risk_names = [t.name for t in high_risk_tools]

        assert "read_file" in safe_names
        assert "execute_command" in high_risk_names

    def test_custom_tool_registration(self):
        """Should allow registering custom tools."""
        registry = ToolRegistry()

        custom_policy = ToolPolicy(
            name="my_custom_tool",
            risk_tier=RiskTier.LIMITED,
            description="A custom tool",
            capabilities=["custom"],
            side_effects=True,
        )
        registry.register(custom_policy)

        assert "my_custom_tool" in registry.list_tools()
        assert registry.get_risk_tier("my_custom_tool") == RiskTier.LIMITED

    def test_validate_args_allowlist(self):
        """Should validate args against allowlist."""
        registry = ToolRegistry()

        # Register tool with allowlist
        policy = ToolPolicy(
            name="restricted_tool",
            risk_tier=RiskTier.LIMITED,
            allowlist=["/allowed/path", "/safe/"],
        )
        registry.register(policy)

        # Valid path
        is_valid, error = registry.validate_args(
            "restricted_tool",
            {"path": "/allowed/path/file.txt"}
        )
        assert is_valid

        # Invalid path
        is_valid, error = registry.validate_args(
            "restricted_tool",
            {"path": "/forbidden/path/file.txt"}
        )
        assert not is_valid
        assert "allowlist" in error.lower()

    def test_validate_args_denylist(self):
        """Should validate args against denylist."""
        registry = ToolRegistry()

        policy = ToolPolicy(
            name="filtered_tool",
            risk_tier=RiskTier.LIMITED,
            denylist=["rm -rf", "sudo", "password"],
        )
        registry.register(policy)

        # Valid command
        is_valid, error = registry.validate_args(
            "filtered_tool",
            {"command": "ls -la"}
        )
        assert is_valid

        # Denied command
        is_valid, error = registry.validate_args(
            "filtered_tool",
            {"command": "rm -rf /"}
        )
        assert not is_valid
        assert "denied" in error.lower()
