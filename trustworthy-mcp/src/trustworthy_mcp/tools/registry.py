"""Tool registry with risk tier classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class RiskTier(IntEnum):
    """Risk classification tiers for tools.

    Tier 0: Read-only safe operations (list directory, read file within workspace)
    Tier 1: Limited side effects (write file within workspace)
    Tier 2: High risk (execute code, network calls, delete, credentials)
    """
    SAFE = 0
    LIMITED = 1
    HIGH_RISK = 2


@dataclass
class ToolPolicy:
    """Policy configuration for a tool."""

    name: str
    risk_tier: RiskTier
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    side_effects: bool = False
    resource_scopes: list[str] = field(default_factory=list)
    approval_required: bool = False
    allowlist: list[str] | None = None
    denylist: list[str] | None = None

    def __post_init__(self) -> None:
        # High-risk tools always require approval
        if self.risk_tier == RiskTier.HIGH_RISK:
            self.approval_required = True
            self.side_effects = True


class ToolRegistry:
    """Registry for tool metadata and risk classification."""

    def __init__(self) -> None:
        self._policies: dict[str, ToolPolicy] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register default tool policies."""
        # Tier 0: Safe read-only operations
        self.register(ToolPolicy(
            name="read_file",
            risk_tier=RiskTier.SAFE,
            description="Read file contents",
            capabilities=["filesystem:read"],
            side_effects=False,
        ))

        self.register(ToolPolicy(
            name="list_directory",
            risk_tier=RiskTier.SAFE,
            description="List directory contents",
            capabilities=["filesystem:read"],
            side_effects=False,
        ))

        self.register(ToolPolicy(
            name="search_files",
            risk_tier=RiskTier.SAFE,
            description="Search for files by pattern",
            capabilities=["filesystem:read"],
            side_effects=False,
        ))

        # Tier 1: Limited side effects
        self.register(ToolPolicy(
            name="write_file",
            risk_tier=RiskTier.LIMITED,
            description="Write content to a file",
            capabilities=["filesystem:write"],
            side_effects=True,
        ))

        self.register(ToolPolicy(
            name="create_directory",
            risk_tier=RiskTier.LIMITED,
            description="Create a new directory",
            capabilities=["filesystem:write"],
            side_effects=True,
        ))

        # Tier 2: High-risk operations
        self.register(ToolPolicy(
            name="execute_command",
            risk_tier=RiskTier.HIGH_RISK,
            description="Execute a shell command",
            capabilities=["exec:shell"],
            side_effects=True,
            approval_required=True,
        ))

        self.register(ToolPolicy(
            name="delete_file",
            risk_tier=RiskTier.HIGH_RISK,
            description="Delete a file",
            capabilities=["filesystem:delete"],
            side_effects=True,
            approval_required=True,
        ))

        self.register(ToolPolicy(
            name="http_request",
            risk_tier=RiskTier.HIGH_RISK,
            description="Make an HTTP request",
            capabilities=["network:http"],
            side_effects=True,
            approval_required=True,
        ))

        # Approval management tools (safe, no approval needed)
        self.register(ToolPolicy(
            name="check_approval_status",
            risk_tier=RiskTier.SAFE,
            description="Check status of a pending approval",
            capabilities=["approval:read"],
            side_effects=False,
        ))

        self.register(ToolPolicy(
            name="list_pending_approvals",
            risk_tier=RiskTier.SAFE,
            description="List all pending approval requests",
            capabilities=["approval:read"],
            side_effects=False,
        ))

        self.register(ToolPolicy(
            name="approve_request",
            risk_tier=RiskTier.SAFE,
            description="Approve a pending request",
            capabilities=["approval:write"],
            side_effects=True,  # Has side effects but no approval needed (it IS the approval)
        ))

        self.register(ToolPolicy(
            name="deny_request",
            risk_tier=RiskTier.SAFE,
            description="Deny a pending request",
            capabilities=["approval:write"],
            side_effects=True,
        ))

    def register(self, policy: ToolPolicy) -> None:
        """Register a tool policy."""
        self._policies[policy.name] = policy

    def get_policy(self, tool_name: str) -> ToolPolicy | None:
        """Get policy for a tool by name."""
        return self._policies.get(tool_name)

    def get_risk_tier(self, tool_name: str) -> RiskTier:
        """Get risk tier for a tool. Defaults to HIGH_RISK for unknown tools."""
        policy = self.get_policy(tool_name)
        if policy is None:
            # Unknown tools are treated as high-risk
            return RiskTier.HIGH_RISK
        return policy.risk_tier

    def requires_approval(self, tool_name: str) -> bool:
        """Check if a tool requires human approval."""
        policy = self.get_policy(tool_name)
        if policy is None:
            # Unknown tools require approval
            return True
        return policy.approval_required

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._policies.keys())

    def list_by_tier(self, tier: RiskTier) -> list[ToolPolicy]:
        """List all tools in a specific risk tier."""
        return [p for p in self._policies.values() if p.risk_tier == tier]

    def validate_args(self, tool_name: str, args: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate tool arguments against policy constraints.

        Returns:
            Tuple of (is_valid, error_message)
        """
        policy = self.get_policy(tool_name)
        if policy is None:
            return True, None  # No policy to validate against

        # Check allowlist if defined
        if policy.allowlist is not None:
            for key, value in args.items():
                if isinstance(value, str):
                    if not any(value.startswith(allowed) for allowed in policy.allowlist):
                        return False, f"Argument '{key}' value not in allowlist"

        # Check denylist if defined
        if policy.denylist is not None:
            for key, value in args.items():
                if isinstance(value, str):
                    if any(denied in value for denied in policy.denylist):
                        return False, f"Argument '{key}' contains denied pattern"

        return True, None
