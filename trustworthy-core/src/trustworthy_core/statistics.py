"""
Detection statistics tracking with rate calculations.

This module provides statistics tracking for security events, including
detection rates, sanitization rates, and halt rates. Originally from
trustworthy-adk's SoftInstructionDefensePlugin.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional


@dataclass
class DetectionStatistics:
    """
    Statistics for injection detection and sanitization.

    Tracks counts of various security events and provides
    computed rate properties.
    """

    total_messages: int = 0
    detected_injections: int = 0
    sanitized_messages: int = 0
    halted_messages: int = 0
    blocked_requests: int = 0
    approved_requests: int = 0
    denied_requests: int = 0

    # Timestamps for rate-over-time calculations
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None

    @property
    def detection_rate(self) -> float:
        """
        Rate of messages that contained detected injections.

        Returns:
            Float from 0.0 to 1.0, or 0.0 if no messages processed.
        """
        if self.total_messages == 0:
            return 0.0
        return self.detected_injections / self.total_messages

    @property
    def sanitization_rate(self) -> float:
        """
        Rate of messages that required sanitization.

        Returns:
            Float from 0.0 to 1.0, or 0.0 if no messages processed.
        """
        if self.total_messages == 0:
            return 0.0
        return self.sanitized_messages / self.total_messages

    @property
    def halt_rate(self) -> float:
        """
        Rate of messages that were halted (blocked entirely).

        Returns:
            Float from 0.0 to 1.0, or 0.0 if no messages processed.
        """
        if self.total_messages == 0:
            return 0.0
        return self.halted_messages / self.total_messages

    @property
    def approval_rate(self) -> float:
        """
        Rate of approval requests that were granted.

        Returns:
            Float from 0.0 to 1.0, or 1.0 if no requests made.
        """
        total_requests = self.approved_requests + self.denied_requests
        if total_requests == 0:
            return 1.0  # No denials = 100% approval
        return self.approved_requests / total_requests

    @property
    def defense_effectiveness(self) -> float:
        """
        Rate of detected injections that were blocked or sanitized.

        Returns:
            Float from 0.0 to 1.0, or 1.0 if no injections detected.
        """
        if self.detected_injections == 0:
            return 1.0  # No attacks = effective defense
        blocked_or_sanitized = self.blocked_requests + self.sanitized_messages
        return min(blocked_or_sanitized / self.detected_injections, 1.0)

    def record_message(self) -> None:
        """Record a new message being processed."""
        self.total_messages += 1
        now = datetime.utcnow()
        if self.first_event is None:
            self.first_event = now
        self.last_event = now

    def record_detection(self) -> None:
        """Record an injection detection."""
        self.detected_injections += 1

    def record_sanitization(self) -> None:
        """Record a sanitization event."""
        self.sanitized_messages += 1

    def record_halt(self) -> None:
        """Record a message being halted."""
        self.halted_messages += 1
        self.blocked_requests += 1

    def record_approval(self, approved: bool) -> None:
        """Record an approval decision."""
        if approved:
            self.approved_requests += 1
        else:
            self.denied_requests += 1

    def reset(self) -> None:
        """Reset all statistics to zero."""
        self.total_messages = 0
        self.detected_injections = 0
        self.sanitized_messages = 0
        self.halted_messages = 0
        self.blocked_requests = 0
        self.approved_requests = 0
        self.denied_requests = 0
        self.first_event = None
        self.last_event = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "counts": {
                "total_messages": self.total_messages,
                "detected_injections": self.detected_injections,
                "sanitized_messages": self.sanitized_messages,
                "halted_messages": self.halted_messages,
                "blocked_requests": self.blocked_requests,
                "approved_requests": self.approved_requests,
                "denied_requests": self.denied_requests,
            },
            "rates": {
                "detection_rate": round(self.detection_rate, 4),
                "sanitization_rate": round(self.sanitization_rate, 4),
                "halt_rate": round(self.halt_rate, 4),
                "approval_rate": round(self.approval_rate, 4),
                "defense_effectiveness": round(self.defense_effectiveness, 4),
            },
            "timestamps": {
                "first_event": self.first_event.isoformat() if self.first_event else None,
                "last_event": self.last_event.isoformat() if self.last_event else None,
            },
        }

    def get_summary(self) -> str:
        """Get a human-readable summary of statistics."""
        lines = [
            "=== Detection Statistics ===",
            "",
            "Counts:",
            f"  Total messages: {self.total_messages}",
            f"  Detected injections: {self.detected_injections}",
            f"  Sanitized messages: {self.sanitized_messages}",
            f"  Halted messages: {self.halted_messages}",
            f"  Approved requests: {self.approved_requests}",
            f"  Denied requests: {self.denied_requests}",
            "",
            "Rates:",
            f"  Detection rate: {self.detection_rate:.1%}",
            f"  Sanitization rate: {self.sanitization_rate:.1%}",
            f"  Halt rate: {self.halt_rate:.1%}",
            f"  Approval rate: {self.approval_rate:.1%}",
            f"  Defense effectiveness: {self.defense_effectiveness:.1%}",
        ]
        return "\n".join(lines)


@dataclass
class SessionStatistics:
    """
    Statistics for a single session, combining detection stats
    with timing and context information.
    """

    session_id: str
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    detection_stats: DetectionStatistics = field(default_factory=DetectionStatistics)

    # Tool usage tracking
    tool_calls: Dict[str, int] = field(default_factory=dict)
    high_risk_tool_calls: int = 0

    def record_tool_call(self, tool_name: str, is_high_risk: bool = False) -> None:
        """Record a tool call."""
        self.tool_calls[tool_name] = self.tool_calls.get(tool_name, 0) + 1
        if is_high_risk:
            self.high_risk_tool_calls += 1

    def end_session(self) -> None:
        """Mark the session as ended."""
        self.end_time = datetime.utcnow()

    @property
    def duration_seconds(self) -> float:
        """Get session duration in seconds."""
        end = self.end_time or datetime.utcnow()
        return (end - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "detection_stats": self.detection_stats.to_dict(),
            "tool_usage": {
                "calls_by_tool": self.tool_calls,
                "total_calls": sum(self.tool_calls.values()),
                "high_risk_calls": self.high_risk_tool_calls,
            },
        }
