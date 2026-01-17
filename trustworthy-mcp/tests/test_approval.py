"""Tests for approval manager."""

import pytest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'trustworthy-core', 'src'))

from trustworthy_mcp.approval.manager import (
    ApprovalManager,
    ApprovalStatus,
    PendingApproval,
)


class TestApprovalManager:
    """Test approval manager functionality."""

    def test_create_approval_request(self):
        """Should create a pending approval request."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="execute_command",
            arguments={"command": "ls -la"},
        )

        assert approval.approval_id.startswith("apr_")
        assert approval.tool_name == "execute_command"
        assert approval.status == ApprovalStatus.PENDING
        assert approval.arguments == {"command": "ls -la"}
        assert approval.expires_at > datetime.utcnow()

    def test_get_pending(self):
        """Should retrieve pending approval by ID."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="test_tool",
            arguments={},
        )

        retrieved = manager.get_pending(approval.approval_id)
        assert retrieved is not None
        assert retrieved.approval_id == approval.approval_id

    def test_get_pending_not_found(self):
        """Should return None for unknown approval ID."""
        manager = ApprovalManager()
        assert manager.get_pending("apr_nonexistent") is None

    def test_approve_creates_token(self):
        """Approving should generate a valid token."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="execute_command",
            arguments={"command": "echo hello"},
        )

        token = manager.approve(approval.approval_id, approved_by="test_user")

        assert token is not None
        assert len(token.token) > 20  # Secure token
        assert token.tool_name == "execute_command"
        assert token.approval_id == approval.approval_id

        # Approval should be marked approved
        updated = manager.get_pending(approval.approval_id)
        assert updated.status == ApprovalStatus.APPROVED
        assert updated.approved_by == "test_user"

    def test_deny(self):
        """Should mark approval as denied."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="dangerous_tool",
            arguments={},
        )

        result = manager.deny(approval.approval_id, reason="Too risky")

        assert result is True
        updated = manager.get_pending(approval.approval_id)
        assert updated.status == ApprovalStatus.DENIED
        assert updated.denial_reason == "Too risky"

    def test_verify_token_valid(self):
        """Should verify a valid token."""
        manager = ApprovalManager()
        args = {"command": "echo test"}

        approval = manager.create_approval_request(
            tool_name="execute_command",
            arguments=args,
        )
        token = manager.approve(approval.approval_id)

        is_valid, error = manager.verify_token(
            token.token,
            "execute_command",
            args,
        )

        assert is_valid
        assert error == ""

    def test_verify_token_invalid(self):
        """Should reject invalid token."""
        manager = ApprovalManager()

        is_valid, error = manager.verify_token(
            "invalid_token",
            "execute_command",
            {},
        )

        assert not is_valid
        assert "invalid" in error.lower()

    def test_verify_token_wrong_tool(self):
        """Should reject token used for different tool."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="tool_a",
            arguments={},
        )
        token = manager.approve(approval.approval_id)

        is_valid, error = manager.verify_token(
            token.token,
            "tool_b",  # Wrong tool
            {},
        )

        assert not is_valid
        assert "tool" in error.lower()

    def test_verify_token_modified_args(self):
        """Should reject token when args have changed."""
        manager = ApprovalManager()
        original_args = {"command": "echo hello"}
        modified_args = {"command": "rm -rf /"}  # Different command

        approval = manager.create_approval_request(
            tool_name="execute_command",
            arguments=original_args,
        )
        token = manager.approve(approval.approval_id)

        is_valid, error = manager.verify_token(
            token.token,
            "execute_command",
            modified_args,
        )

        assert not is_valid
        assert "arguments" in error.lower()

    def test_token_single_use(self):
        """Token should be consumed after verification."""
        manager = ApprovalManager()
        args = {"test": "value"}

        approval = manager.create_approval_request(
            tool_name="test_tool",
            arguments=args,
        )
        token = manager.approve(approval.approval_id)

        # First use should succeed
        is_valid, _ = manager.verify_token(token.token, "test_tool", args)
        assert is_valid

        # Second use should fail
        is_valid, error = manager.verify_token(token.token, "test_tool", args)
        assert not is_valid

    def test_list_pending(self):
        """Should list all pending approvals."""
        manager = ApprovalManager()

        # Create multiple approvals
        a1 = manager.create_approval_request("tool1", {})
        a2 = manager.create_approval_request("tool2", {})

        # Approve one
        manager.approve(a1.approval_id)

        pending = manager.list_pending()
        pending_ids = [p.approval_id for p in pending]

        assert a2.approval_id in pending_ids
        assert a1.approval_id not in pending_ids  # Already approved

    def test_cleanup_expired(self):
        """Should clean up expired approvals."""
        manager = ApprovalManager(default_expiry_minutes=0)  # Immediate expiry

        # Create approval that expires immediately
        approval = manager.create_approval_request("test", {})

        # Wait a moment and cleanup
        import time
        time.sleep(0.1)
        cleaned = manager.cleanup_expired()

        assert cleaned >= 1
        assert manager.get_pending(approval.approval_id) is None

    def test_format_for_display(self):
        """Should format approval for display."""
        manager = ApprovalManager()

        approval = manager.create_approval_request(
            tool_name="execute_command",
            arguments={"command": "ls -la", "cwd": "/tmp"},
        )

        display = manager.format_for_display(approval)

        assert "APPROVAL REQUIRED" in display
        assert "execute_command" in display
        assert approval.approval_id in display
        assert "ls -la" in display
