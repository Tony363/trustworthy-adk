"""Approval manager for HITL (Human-in-the-Loop) operations."""

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class PendingApproval:
    """A pending approval request."""
    approval_id: str
    tool_name: str
    arguments: dict[str, Any]
    args_hash: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_at: datetime | None = None
    approved_by: str | None = None
    denial_reason: str | None = None


@dataclass
class ApprovalToken:
    """A token proving approval was granted."""
    token: str
    approval_id: str
    tool_name: str
    args_hash: str
    expires_at: datetime


class ApprovalManager:
    """Manages human-in-the-loop approvals for sensitive operations.

    Implements the approval flow:
    1. Tool call arrives requiring approval
    2. Create pending approval and return approval_id
    3. Human reviews and approves/denies
    4. If approved, generate approval token
    5. Client re-submits with approval token
    6. Verify token matches original request
    """

    def __init__(
        self,
        default_expiry_minutes: int = 30,
        token_expiry_minutes: int = 5,
    ) -> None:
        """Initialize the approval manager.

        Args:
            default_expiry_minutes: How long pending approvals remain valid
            token_expiry_minutes: How long approval tokens remain valid
        """
        self.default_expiry_minutes = default_expiry_minutes
        self.token_expiry_minutes = token_expiry_minutes
        self._pending: dict[str, PendingApproval] = {}
        self._tokens: dict[str, ApprovalToken] = {}

    def _hash_args(self, tool_name: str, args: dict[str, Any]) -> str:
        """Create a stable hash of tool name and arguments."""
        # Canonicalize by sorting keys
        canonical = json.dumps({"tool": tool_name, "args": args}, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def _generate_id(self) -> str:
        """Generate a unique approval ID."""
        return f"apr_{secrets.token_urlsafe(12)}"

    def _generate_token(self) -> str:
        """Generate a secure approval token."""
        return secrets.token_urlsafe(32)

    def create_approval_request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        expiry_minutes: int | None = None,
    ) -> PendingApproval:
        """Create a new pending approval request.

        Args:
            tool_name: Name of the tool requiring approval
            arguments: Tool arguments to approve
            expiry_minutes: Custom expiry time

        Returns:
            PendingApproval object with approval_id
        """
        now = datetime.utcnow()
        expiry = expiry_minutes or self.default_expiry_minutes

        approval = PendingApproval(
            approval_id=self._generate_id(),
            tool_name=tool_name,
            arguments=arguments,
            args_hash=self._hash_args(tool_name, arguments),
            created_at=now,
            expires_at=now + timedelta(minutes=expiry),
        )

        self._pending[approval.approval_id] = approval
        logger.info(f"Created approval request {approval.approval_id} for {tool_name}")

        return approval

    def get_pending(self, approval_id: str) -> PendingApproval | None:
        """Get a pending approval by ID."""
        approval = self._pending.get(approval_id)
        if approval and approval.expires_at < datetime.utcnow():
            approval.status = ApprovalStatus.EXPIRED
        return approval

    def approve(
        self,
        approval_id: str,
        approved_by: str = "user",
    ) -> ApprovalToken | None:
        """Approve a pending request and generate an approval token.

        Args:
            approval_id: ID of the approval to grant
            approved_by: Identifier of who approved

        Returns:
            ApprovalToken if successful, None if approval not found/expired
        """
        approval = self.get_pending(approval_id)
        if approval is None:
            logger.warning(f"Approval {approval_id} not found")
            return None

        if approval.status == ApprovalStatus.EXPIRED:
            logger.warning(f"Approval {approval_id} has expired")
            return None

        if approval.status != ApprovalStatus.PENDING:
            logger.warning(f"Approval {approval_id} is not pending (status: {approval.status})")
            return None

        # Update approval status
        approval.status = ApprovalStatus.APPROVED
        approval.approved_at = datetime.utcnow()
        approval.approved_by = approved_by

        # Generate token
        now = datetime.utcnow()
        token = ApprovalToken(
            token=self._generate_token(),
            approval_id=approval_id,
            tool_name=approval.tool_name,
            args_hash=approval.args_hash,
            expires_at=now + timedelta(minutes=self.token_expiry_minutes),
        )

        self._tokens[token.token] = token
        logger.info(f"Approved {approval_id}, token expires at {token.expires_at}")

        return token

    def issue_token(
        self,
        approval_id: str,
    ) -> ApprovalToken | None:
        """Issue a new token for an already-approved request.

        This is used when checking approval status to provide a usable token
        for requests that have been approved by a human operator.

        Args:
            approval_id: ID of the approved request

        Returns:
            ApprovalToken if successful, None if approval not found/not approved
        """
        approval = self.get_pending(approval_id)
        if approval is None:
            logger.warning(f"Approval {approval_id} not found")
            return None

        if approval.status != ApprovalStatus.APPROVED:
            logger.warning(f"Approval {approval_id} is not approved (status: {approval.status})")
            return None

        # Check if approval has expired
        if approval.expires_at < datetime.utcnow():
            approval.status = ApprovalStatus.EXPIRED
            return None

        # Generate a new token
        now = datetime.utcnow()
        token = ApprovalToken(
            token=self._generate_token(),
            approval_id=approval_id,
            tool_name=approval.tool_name,
            args_hash=approval.args_hash,
            expires_at=now + timedelta(minutes=self.token_expiry_minutes),
        )

        self._tokens[token.token] = token
        logger.info(f"Issued new token for approved {approval_id}")

        return token

    def deny(
        self,
        approval_id: str,
        reason: str | None = None,
    ) -> bool:
        """Deny a pending approval request.

        Args:
            approval_id: ID of the approval to deny
            reason: Optional reason for denial

        Returns:
            True if denial was recorded
        """
        approval = self.get_pending(approval_id)
        if approval is None or approval.status != ApprovalStatus.PENDING:
            return False

        approval.status = ApprovalStatus.DENIED
        approval.denial_reason = reason
        logger.info(f"Denied approval {approval_id}: {reason}")

        return True

    def verify_token(
        self,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        """Verify an approval token matches the current request.

        Args:
            token: The approval token to verify
            tool_name: Tool name being called
            arguments: Tool arguments being used

        Returns:
            Tuple of (is_valid, error_message)
        """
        approval_token = self._tokens.get(token)
        if approval_token is None:
            return False, "Invalid approval token"

        if approval_token.expires_at < datetime.utcnow():
            del self._tokens[token]
            return False, "Approval token has expired"

        if approval_token.tool_name != tool_name:
            return False, f"Token is for tool '{approval_token.tool_name}', not '{tool_name}'"

        expected_hash = self._hash_args(tool_name, arguments)
        if approval_token.args_hash != expected_hash:
            return False, "Token does not match current arguments (arguments have changed)"

        # Token is valid - remove it (single use)
        del self._tokens[token]
        logger.info(f"Verified and consumed token for {tool_name}")

        return True, ""

    def list_pending(self) -> list[PendingApproval]:
        """List all pending approvals (not expired)."""
        now = datetime.utcnow()
        pending = []
        for approval in self._pending.values():
            if approval.status == ApprovalStatus.PENDING:
                if approval.expires_at >= now:
                    pending.append(approval)
                else:
                    approval.status = ApprovalStatus.EXPIRED
        return pending

    def cleanup_expired(self) -> int:
        """Remove expired approvals and tokens.

        Returns:
            Number of items cleaned up
        """
        now = datetime.utcnow()
        cleaned = 0

        # Clean expired pending approvals
        expired_ids = [
            aid for aid, a in self._pending.items()
            if a.expires_at < now
        ]
        for aid in expired_ids:
            del self._pending[aid]
            cleaned += 1

        # Clean expired tokens
        expired_tokens = [
            t for t, tok in self._tokens.items()
            if tok.expires_at < now
        ]
        for t in expired_tokens:
            del self._tokens[t]
            cleaned += 1

        if cleaned > 0:
            logger.debug(f"Cleaned up {cleaned} expired approvals/tokens")

        return cleaned

    def format_for_display(self, approval: PendingApproval) -> str:
        """Format a pending approval for display to the user.

        Args:
            approval: The pending approval to format

        Returns:
            Human-readable string for CLI display
        """
        lines = [
            f"{'='*60}",
            f"APPROVAL REQUIRED: {approval.tool_name}",
            f"{'='*60}",
            f"Approval ID: {approval.approval_id}",
            f"Expires: {approval.expires_at.isoformat()}",
            "",
            "Arguments:",
        ]

        for key, value in approval.arguments.items():
            if isinstance(value, str) and len(value) > 100:
                value = value[:100] + "..."
            lines.append(f"  {key}: {value}")

        lines.extend([
            "",
            "To approve, call check_approval_status with this approval_id",
            f"{'='*60}",
        ])

        return "\n".join(lines)
