"""Audit logging for security events and tool calls.

Includes tool-call profiling metrics inspired by the Agentic Profiler
from trustworthy-adk. Tracks autonomy scores and risk patterns over time.

Enhanced with full 4D rubric support from trustworthy-core:
- Autonomy (L1-L5)
- Efficacy (E.0-E.5)
- Goal Complexity (GC.0-GC.5)
- Generality (G.1-G.5)
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# Import 4D rubric from trustworthy-core
from trustworthy_core.rubric import (
    AutonomyLevel,
    EfficacyLevel,
    GoalComplexityLevel,
    GeneralityLevel,
)
from trustworthy_core.statistics import DetectionStatistics

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


@dataclass
class SecurityProfile:
    """Security profile metrics implementing the full Agentic Profiler 4D framework.

    The 4D rubric dimensions from trustworthy-core:
    - Autonomy (L1-L5): Level of human oversight in decision-making
    - Efficacy (E.0-E.5): Scope of actions the agent can take
    - Goal Complexity (GC.0-GC.5): Sophistication of task planning
    - Generality (G.1-G.5): Breadth of domains the agent can operate in

    Also tracks:
    - Risk exposure: Frequency of high-risk operations
    - Approval compliance: Ratio of approved vs blocked operations
    - Detection statistics: Injection detection/sanitization rates
    """
    # Time window for metrics
    window_start: datetime
    window_end: datetime

    # Tool usage counts by risk tier
    tier_0_calls: int = 0  # Safe operations
    tier_1_calls: int = 0  # Limited side effects
    tier_2_calls: int = 0  # High-risk operations

    # Security event counts
    injection_attempts: int = 0
    injection_blocked: int = 0
    approvals_requested: int = 0
    approvals_granted: int = 0
    approvals_denied: int = 0
    policy_violations: int = 0

    # === NEW: Full 4D Rubric Levels ===
    autonomy_level: Optional[AutonomyLevel] = None
    efficacy_level: Optional[EfficacyLevel] = None
    goal_complexity: Optional[GoalComplexityLevel] = None
    generality: Optional[GeneralityLevel] = None

    # === NEW: Detection Statistics from trustworthy-core ===
    detection_stats: DetectionStatistics = field(default_factory=DetectionStatistics)

    # Derived metrics (0.0 to 1.0 scale)
    @property
    def autonomy_score(self) -> float:
        """Score indicating level of autonomous operation.

        If autonomy_level is set (from 4D profiling), use its numeric value.
        Otherwise, derive from tool call patterns.

        Higher score = more high-risk operations without human oversight.
        Lower score = more cautious, approval-seeking behavior.
        """
        # Prefer 4D rubric level if available
        if self.autonomy_level is not None:
            return self.autonomy_level.numeric / 5.0

        # Fallback to tier-based calculation
        total = self.tier_0_calls + self.tier_1_calls + self.tier_2_calls
        if total == 0:
            return 0.0

        # Weight by risk tier
        weighted = (
            self.tier_0_calls * 0.1 +
            self.tier_1_calls * 0.3 +
            self.tier_2_calls * 0.8
        )
        max_weighted = total * 0.8  # If all were tier 2
        return min(weighted / max_weighted, 1.0) if max_weighted > 0 else 0.0

    @property
    def efficacy_score(self) -> float:
        """Score indicating scope of agent's actions (0.0 to 1.0).

        From 4D rubric: E.0 (observation only) to E.5 (unbounded physical).
        """
        if self.efficacy_level is not None:
            return self.efficacy_level.numeric / 5.0
        # Default estimation based on tier 2 calls (high-risk = higher efficacy)
        total = self.tier_0_calls + self.tier_1_calls + self.tier_2_calls
        if total == 0:
            return 0.0
        return min((self.tier_2_calls * 2 + self.tier_1_calls) / total, 1.0)

    @property
    def goal_complexity_score(self) -> float:
        """Score indicating sophistication of task planning (0.0 to 1.0).

        From 4D rubric: GC.0 (no goal) to GC.5 (autopoietic).
        """
        if self.goal_complexity is not None:
            return self.goal_complexity.numeric / 5.0
        # Default: estimate from total operations (more calls = more complex task)
        total = self.tier_0_calls + self.tier_1_calls + self.tier_2_calls
        return min(total / 50.0, 1.0)  # Saturates at 50 operations

    @property
    def generality_score(self) -> float:
        """Score indicating breadth of domains (0.0 to 1.0).

        From 4D rubric: G.1 (narrow) to G.5 (super-general).
        """
        if self.generality is not None:
            return self.generality.numeric / 5.0
        # Default: estimate from tool diversity (not implemented without tool tracking)
        return 0.4  # Default to domain-specific (G.2)

    @property
    def risk_exposure_score(self) -> float:
        """Score indicating exposure to security risks.

        Higher score = more injection attempts, policy violations.
        """
        risky_events = self.injection_attempts + self.policy_violations
        total_events = (
            self.tier_0_calls + self.tier_1_calls + self.tier_2_calls +
            risky_events
        )
        if total_events == 0:
            return 0.0
        return min(risky_events / total_events, 1.0)

    @property
    def approval_compliance_score(self) -> float:
        """Score indicating compliance with approval requirements.

        Higher score = more approvals granted vs denied.
        1.0 = perfect compliance, 0.0 = all requests denied.
        """
        total_requests = self.approvals_granted + self.approvals_denied
        if total_requests == 0:
            return 1.0  # No denials = compliant
        return self.approvals_granted / total_requests

    @property
    def defense_effectiveness_score(self) -> float:
        """Score indicating how effective defenses are.

        Higher score = more injections blocked vs attempted.
        """
        if self.injection_attempts == 0:
            return 1.0  # No attacks = effective (nothing to block)
        return self.injection_blocked / self.injection_attempts

    @property
    def total_risk_score(self) -> float:
        """Composite risk score combining 4D rubric dimensions.

        Higher score = higher risk profile requiring more oversight.
        """
        # Weight each dimension by risk contribution
        weights = {
            "autonomy": 0.3,
            "efficacy": 0.35,
            "goal_complexity": 0.2,
            "generality": 0.15,
        }

        return (
            weights["autonomy"] * self.autonomy_score +
            weights["efficacy"] * self.efficacy_score +
            weights["goal_complexity"] * self.goal_complexity_score +
            weights["generality"] * self.generality_score
        )

    def set_rubric_levels(
        self,
        autonomy: Optional[AutonomyLevel] = None,
        efficacy: Optional[EfficacyLevel] = None,
        goal_complexity: Optional[GoalComplexityLevel] = None,
        generality: Optional[GeneralityLevel] = None,
    ) -> None:
        """Set 4D rubric levels from intent profiling."""
        if autonomy is not None:
            self.autonomy_level = autonomy
        if efficacy is not None:
            self.efficacy_level = efficacy
        if goal_complexity is not None:
            self.goal_complexity = goal_complexity
        if generality is not None:
            self.generality = generality

    def get_rubric_dict(self) -> dict[str, Any]:
        """Get 4D rubric as dictionary for visualization."""
        return {
            "Autonomy": self.autonomy_score * 5,  # Scale to 0-5 for radar chart
            "Efficacy": self.efficacy_score * 5,
            "Goal Complexity": self.goal_complexity_score * 5,
            "Generality": self.generality_score * 5,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "tool_usage": {
                "tier_0_safe": self.tier_0_calls,
                "tier_1_limited": self.tier_1_calls,
                "tier_2_high_risk": self.tier_2_calls,
                "total": self.tier_0_calls + self.tier_1_calls + self.tier_2_calls,
            },
            "security_events": {
                "injection_attempts": self.injection_attempts,
                "injection_blocked": self.injection_blocked,
                "approvals_requested": self.approvals_requested,
                "approvals_granted": self.approvals_granted,
                "approvals_denied": self.approvals_denied,
                "policy_violations": self.policy_violations,
            },
            "rubric_4d": {
                "autonomy": {
                    "level": self.autonomy_level.level if self.autonomy_level else None,
                    "label": self.autonomy_level.label if self.autonomy_level else None,
                    "score": round(self.autonomy_score, 3),
                },
                "efficacy": {
                    "level": self.efficacy_level.level if self.efficacy_level else None,
                    "label": self.efficacy_level.label if self.efficacy_level else None,
                    "score": round(self.efficacy_score, 3),
                },
                "goal_complexity": {
                    "level": self.goal_complexity.level if self.goal_complexity else None,
                    "label": self.goal_complexity.label if self.goal_complexity else None,
                    "score": round(self.goal_complexity_score, 3),
                },
                "generality": {
                    "level": self.generality.level if self.generality else None,
                    "label": self.generality.label if self.generality else None,
                    "score": round(self.generality_score, 3),
                },
                "total_risk_score": round(self.total_risk_score, 3),
            },
            "detection_stats": self.detection_stats.to_dict(),
            "scores": {
                "autonomy": round(self.autonomy_score, 3),
                "efficacy": round(self.efficacy_score, 3),
                "goal_complexity": round(self.goal_complexity_score, 3),
                "generality": round(self.generality_score, 3),
                "risk_exposure": round(self.risk_exposure_score, 3),
                "approval_compliance": round(self.approval_compliance_score, 3),
                "defense_effectiveness": round(self.defense_effectiveness_score, 3),
                "total_risk": round(self.total_risk_score, 3),
            },
        }


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

    def get_security_profile(
        self,
        window_minutes: int = 60,
    ) -> SecurityProfile:
        """Generate a security profile from recent events.

        This implements a subset of the Agentic Profiler's 4D framework,
        tracking metrics that can be derived from tool call patterns.

        Args:
            window_minutes: Time window for metrics (default: last hour)

        Returns:
            SecurityProfile with computed metrics
        """
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)

        # Filter events to window
        window_events = [
            e for e in self._events
            if e.timestamp >= window_start
        ]

        profile = SecurityProfile(
            window_start=window_start,
            window_end=now,
        )

        for event in window_events:
            if event.event_type == AuditEventType.TOOL_CALL:
                # Count by risk tier
                tier = event.risk_tier or 0
                if tier == 0:
                    profile.tier_0_calls += 1
                elif tier == 1:
                    profile.tier_1_calls += 1
                else:
                    profile.tier_2_calls += 1

            elif event.event_type == AuditEventType.INJECTION_DETECTED:
                profile.injection_attempts += 1

            elif event.event_type == AuditEventType.INJECTION_BLOCKED:
                profile.injection_attempts += 1
                profile.injection_blocked += 1

            elif event.event_type == AuditEventType.APPROVAL_REQUESTED:
                profile.approvals_requested += 1

            elif event.event_type == AuditEventType.APPROVAL_GRANTED:
                profile.approvals_granted += 1

            elif event.event_type == AuditEventType.APPROVAL_DENIED:
                profile.approvals_denied += 1

            elif event.event_type == AuditEventType.POLICY_VIOLATION:
                profile.policy_violations += 1

        return profile

    def get_profile_summary(self, window_minutes: int = 60) -> str:
        """Get a human-readable security profile summary.

        Args:
            window_minutes: Time window for metrics

        Returns:
            Formatted summary string
        """
        profile = self.get_security_profile(window_minutes)
        data = profile.to_dict()
        scores = data["scores"]
        rubric = data["rubric_4d"]
        stats = data["detection_stats"]

        lines = [
            f"=== Security Profile (last {window_minutes} min) ===",
            "",
            "Tool Usage:",
            f"  - Safe (Tier 0): {profile.tier_0_calls}",
            f"  - Limited (Tier 1): {profile.tier_1_calls}",
            f"  - High-Risk (Tier 2): {profile.tier_2_calls}",
            "",
            "Security Events:",
            f"  - Injection attempts: {profile.injection_attempts}",
            f"  - Injections blocked: {profile.injection_blocked}",
            f"  - Approvals requested: {profile.approvals_requested}",
            f"  - Approvals granted: {profile.approvals_granted}",
            f"  - Approvals denied: {profile.approvals_denied}",
            f"  - Policy violations: {profile.policy_violations}",
            "",
            "4D Rubric Profile:",
            f"  - Autonomy: {rubric['autonomy']['label'] or 'N/A'} ({rubric['autonomy']['level'] or 'estimated'}, score={scores['autonomy']:.2f})",
            f"  - Efficacy: {rubric['efficacy']['label'] or 'N/A'} ({rubric['efficacy']['level'] or 'estimated'}, score={scores['efficacy']:.2f})",
            f"  - Goal Complexity: {rubric['goal_complexity']['label'] or 'N/A'} ({rubric['goal_complexity']['level'] or 'estimated'}, score={scores['goal_complexity']:.2f})",
            f"  - Generality: {rubric['generality']['label'] or 'N/A'} ({rubric['generality']['level'] or 'estimated'}, score={scores['generality']:.2f})",
            f"  - Total Risk Score: {scores['total_risk']:.3f}",
            "",
            "Detection Statistics:",
            f"  - Total messages: {stats['counts']['total_messages']}",
            f"  - Detection rate: {stats['rates']['detection_rate']:.2%}",
            f"  - Sanitization rate: {stats['rates']['sanitization_rate']:.2%}",
            f"  - Halt rate: {stats['rates']['halt_rate']:.2%}",
            "",
            "Security Scores (0.0 - 1.0):",
            f"  - Autonomy: {scores['autonomy']:.2f} (lower = more cautious)",
            f"  - Risk Exposure: {scores['risk_exposure']:.2f} (lower = safer)",
            f"  - Approval Compliance: {scores['approval_compliance']:.2f} (higher = better)",
            f"  - Defense Effectiveness: {scores['defense_effectiveness']:.2f} (higher = better)",
        ]

        return "\n".join(lines)
