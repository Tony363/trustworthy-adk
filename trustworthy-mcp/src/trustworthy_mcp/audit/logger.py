"""Audit logging for security events and tool calls."""

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    INJECTION_DETECTED = "injection_detected"
    INJECTION_BLOCKED = "injection_blocked"
    SANITIZATION_APPLIED = "sanitization_applied"
    POLICY_VIOLATION = "policy_violation"
    ERROR = "error"


@dataclass
class AuditEvent:
    """An audit log event."""
    event_type: AuditEventType
    timestamp: datetime
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    result: str | None = None
    is_error: bool = False
    risk_tier: int | None = None
    approval_id: str | None = None
    classification_result: dict[str, Any] | None = None
    sanitization_warnings: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Logs security-relevant events for audit trail.

    Provides:
    - Structured logging of all tool calls
    - Security event tracking (injections, policy violations)
    - Approval audit trail
    - Optional file-based persistence
    """

    def __init__(
        self,
        log_file: str | Path | None = None,
        max_events: int = 10000,
        redact_sensitive: bool = True,
    ) -> None:
        """Initialize the audit logger.

        Args:
            log_file: Optional path to write audit logs
            max_events: Maximum events to keep in memory
            redact_sensitive: Whether to redact sensitive data in logs
        """
        self.log_file = Path(log_file) if log_file else None
        self.max_events = max_events
        self.redact_sensitive = redact_sensitive
        self._events: list[AuditEvent] = []

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _redact_args(self, args: dict[str, Any] | None) -> dict[str, Any] | None:
        """Redact sensitive information from arguments."""
        if args is None or not self.redact_sensitive:
            return args

        sensitive_keys = {"password", "secret", "token", "key", "credential", "auth"}
        redacted = {}

        for key, value in args.items():
            key_lower = key.lower()
            if any(s in key_lower for s in sensitive_keys):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 500:
                redacted[key] = value[:500] + "...[TRUNCATED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_args(value)
            else:
                redacted[key] = value

        return redacted

    def _add_event(self, event: AuditEvent) -> None:
        """Add an event to the log."""
        self._events.append(event)

        # Trim if over max
        if len(self._events) > self.max_events:
            self._events = self._events[-self.max_events:]

        # Write to file if configured
        if self.log_file:
            try:
                with open(self.log_file, "a") as f:
                    f.write(event.to_json() + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit log: {e}")

        # Also log via standard logger
        logger.info(f"AUDIT: {event.event_type.value} - {event.tool_name or 'system'}")

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        risk_tier: int,
    ) -> None:
        """Log a tool call attempt."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            arguments=self._redact_args(arguments),
            risk_tier=risk_tier,
        ))

    def log_tool_result(
        self,
        tool_name: str,
        result: str,
        is_error: bool = False,
    ) -> None:
        """Log a tool call result."""
        result_preview = result[:200] + "..." if len(result) > 200 else result
        self._add_event(AuditEvent(
            event_type=AuditEventType.TOOL_RESULT,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            result=result_preview,
            is_error=is_error,
        ))

    def log_approval_requested(
        self,
        tool_name: str,
        approval_id: str,
        arguments: dict[str, Any],
    ) -> None:
        """Log an approval request."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            approval_id=approval_id,
            arguments=self._redact_args(arguments),
        ))

    def log_approval_granted(
        self,
        tool_name: str,
        approval_id: str,
        approved_by: str | None = None,
    ) -> None:
        """Log an approval being granted."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.APPROVAL_GRANTED,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            approval_id=approval_id,
            metadata={"approved_by": approved_by} if approved_by else {},
        ))

    def log_approval_denied(
        self,
        tool_name: str,
        approval_id: str,
        reason: str | None = None,
    ) -> None:
        """Log an approval being denied."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.APPROVAL_DENIED,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            approval_id=approval_id,
            metadata={"reason": reason} if reason else {},
        ))

    def log_injection_detected(
        self,
        tool_name: str,
        classification_result: dict[str, Any],
        blocked: bool = False,
    ) -> None:
        """Log a detected injection attempt."""
        event_type = (
            AuditEventType.INJECTION_BLOCKED if blocked
            else AuditEventType.INJECTION_DETECTED
        )
        self._add_event(AuditEvent(
            event_type=event_type,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            classification_result=classification_result,
        ))

    def log_sanitization(
        self,
        tool_name: str,
        warnings: list[str],
    ) -> None:
        """Log sanitization being applied."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.SANITIZATION_APPLIED,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            sanitization_warnings=warnings,
        ))

    def log_policy_violation(
        self,
        tool_name: str,
        violation: str,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Log a policy violation."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.POLICY_VIOLATION,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            arguments=self._redact_args(arguments),
            metadata={"violation": violation},
        ))

    def log_error(
        self,
        tool_name: str | None,
        error: str,
    ) -> None:
        """Log an error."""
        self._add_event(AuditEvent(
            event_type=AuditEventType.ERROR,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            is_error=True,
            metadata={"error": error},
        ))

    def get_recent_events(self, count: int = 100) -> list[AuditEvent]:
        """Get recent audit events.

        Args:
            count: Number of events to return

        Returns:
            List of most recent events
        """
        return self._events[-count:]

    def get_events_by_type(self, event_type: AuditEventType) -> list[AuditEvent]:
        """Get events of a specific type."""
        return [e for e in self._events if e.event_type == event_type]

    def get_security_events(self) -> list[AuditEvent]:
        """Get all security-relevant events."""
        security_types = {
            AuditEventType.INJECTION_DETECTED,
            AuditEventType.INJECTION_BLOCKED,
            AuditEventType.POLICY_VIOLATION,
            AuditEventType.APPROVAL_DENIED,
        }
        return [e for e in self._events if e.event_type in security_types]

    def export_json(self, filepath: str | Path) -> None:
        """Export all events to a JSON file.

        Args:
            filepath: Path to write the export
        """
        with open(filepath, "w") as f:
            json.dump([e.to_dict() for e in self._events], f, indent=2)

    def clear(self) -> None:
        """Clear all events from memory (does not affect log file)."""
        self._events = []
