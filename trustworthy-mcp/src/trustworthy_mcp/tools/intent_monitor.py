"""
Intent Monitor Tool - 4D Profiling for Claude Code sessions.

This tool enables the 4D agent profiling rubric (Autonomy, Efficacy, Goal
Complexity, Generality) for Claude Code sessions. Since MCP cannot see
the main conversation, this tool allows Claude to proactively share its
task intent for profiling.

Usage in Claude Code:
    # At the start of a complex task
    monitor_intent(
        task_description="Refactor the authentication module",
        expected_tools=["read_file", "write_file", "execute_command"],
        autonomy_level="consultant"
    )

The profile is then used to:
- Adjust approval requirements
- Track risk exposure
- Provide context in security reports
"""

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any

# Import from trustworthy-core
from trustworthy_core.rubric import (
    AutonomyLevel,
    EfficacyLevel,
    GoalComplexityLevel,
    GeneralityLevel,
    estimate_rubric_from_tools,
)
from trustworthy_core.statistics import DetectionStatistics

logger = logging.getLogger(__name__)


@dataclass
class IntentProfile:
    """
    Profile of the current session's intent and capabilities.

    This is set by calling monitor_intent() at the start of a task.
    """

    # Task description
    task_description: str
    expected_tools: List[str]

    # 4D Rubric levels
    autonomy_level: AutonomyLevel = AutonomyLevel.COLLABORATOR
    efficacy_level: EfficacyLevel = EfficacyLevel.OBSERVATION_ONLY
    goal_complexity: GoalComplexityLevel = GoalComplexityLevel.SEQUENTIAL
    generality: GeneralityLevel = GeneralityLevel.DOMAIN_SPECIFIC

    # Computed properties
    risk_score: float = 0.0
    tools_requiring_approval: List[str] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

    # Session tracking
    detection_stats: DetectionStatistics = field(default_factory=DetectionStatistics)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_description": self.task_description,
            "expected_tools": self.expected_tools,
            "rubric": {
                "autonomy": {
                    "level": self.autonomy_level.level,
                    "label": self.autonomy_level.label,
                },
                "efficacy": {
                    "level": self.efficacy_level.level,
                    "label": self.efficacy_level.label,
                },
                "goal_complexity": {
                    "level": self.goal_complexity.level,
                    "label": self.goal_complexity.label,
                },
                "generality": {
                    "level": self.generality.level,
                    "label": self.generality.label,
                },
            },
            "risk_score": round(self.risk_score, 3),
            "tools_requiring_approval": self.tools_requiring_approval,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "detection_stats": self.detection_stats.to_dict(),
        }


# Global session profile (per-process)
_current_profile: Optional[IntentProfile] = None


def monitor_intent(
    task_description: str,
    expected_tools: List[str],
    autonomy_level: str = "collaborator",
) -> Dict[str, Any]:
    """
    Register the intent for the current task.

    This tool should be called at the start of complex tasks to enable
    4D profiling. The profile is used to:
    - Estimate goal complexity and generality
    - Determine which tools need approval
    - Track security metrics for the session

    Args:
        task_description: Description of what the task aims to accomplish
        expected_tools: List of tool names expected to be used
        autonomy_level: Desired autonomy level (operator/collaborator/consultant/approver/observer)

    Returns:
        Dict with the computed profile and recommendations

    Example:
        >>> monitor_intent(
        ...     task_description="Refactor authentication module",
        ...     expected_tools=["read_file", "write_file", "execute_command"],
        ...     autonomy_level="consultant"
        ... )
        {
            "goal_complexity": {"level": "GC.3", "label": "Adaptive"},
            "generality": {"level": "G.2", "label": "Domain Specific"},
            "risk_assessment": 0.45,
            "recommended_approvals": ["execute_command"]
        }
    """
    global _current_profile

    logger.info(f"Intent monitor: Registering task - {task_description[:50]}...")

    # Parse autonomy level
    autonomy_map = {
        "operator": AutonomyLevel.OPERATOR,
        "collaborator": AutonomyLevel.COLLABORATOR,
        "consultant": AutonomyLevel.CONSULTANT,
        "approver": AutonomyLevel.APPROVER,
        "observer": AutonomyLevel.OBSERVER,
    }
    autonomy = autonomy_map.get(autonomy_level.lower(), AutonomyLevel.COLLABORATOR)

    # Use heuristic estimation from trustworthy-core
    estimated = estimate_rubric_from_tools(
        tools=expected_tools,
        has_human_approval=(autonomy != AutonomyLevel.OBSERVER),
        max_iterations=None,  # Not in action-selector mode
    )

    # Parse estimated levels
    efficacy = _parse_efficacy(estimated["efficacy"]["level"])
    goal_complexity = _parse_goal_complexity(estimated["goal_complexity"]["level"])
    generality = _parse_generality(estimated["generality"]["level"])

    # Calculate risk score
    risk_score = _calculate_risk_score(autonomy, efficacy, goal_complexity, expected_tools)

    # Determine which tools need approval
    high_risk_keywords = ["execute", "command", "delete", "remove", "http", "request", "shell"]
    tools_requiring_approval = [
        tool for tool in expected_tools
        if any(kw in tool.lower() for kw in high_risk_keywords)
    ]

    # Create the profile
    _current_profile = IntentProfile(
        task_description=task_description,
        expected_tools=expected_tools,
        autonomy_level=autonomy,
        efficacy_level=efficacy,
        goal_complexity=goal_complexity,
        generality=generality,
        risk_score=risk_score,
        tools_requiring_approval=tools_requiring_approval,
    )

    logger.info(f"Intent profile created: GC={goal_complexity.level}, G={generality.level}, risk={risk_score:.2f}")

    # Return the profile summary
    return {
        "status": "profile_created",
        "task_description": task_description,
        "goal_complexity": {
            "level": goal_complexity.level,
            "label": goal_complexity.label,
        },
        "generality": {
            "level": generality.level,
            "label": generality.label,
        },
        "autonomy": {
            "level": autonomy.level,
            "label": autonomy.label,
        },
        "efficacy": {
            "level": efficacy.level,
            "label": efficacy.label,
        },
        "risk_assessment": round(risk_score, 3),
        "recommended_approvals": tools_requiring_approval,
        "expected_tool_count": len(expected_tools),
    }


def get_session_profile() -> Optional[IntentProfile]:
    """
    Get the current session's intent profile.

    Returns:
        IntentProfile if one has been set, None otherwise
    """
    return _current_profile


def clear_session_profile() -> None:
    """Clear the current session profile."""
    global _current_profile
    _current_profile = None
    logger.info("Intent profile cleared")


def update_profile_stats(
    detected_injection: bool = False,
    sanitized: bool = False,
    blocked: bool = False,
    approved: Optional[bool] = None,
) -> None:
    """
    Update the session profile's detection statistics.

    Called by other components to track security events.
    """
    global _current_profile

    if _current_profile is None:
        return

    stats = _current_profile.detection_stats
    stats.record_message()

    if detected_injection:
        stats.record_detection()
    if sanitized:
        stats.record_sanitization()
    if blocked:
        stats.record_halt()
    if approved is not None:
        stats.record_approval(approved)

    _current_profile.updated_at = datetime.utcnow()


def _parse_efficacy(level: str) -> EfficacyLevel:
    """Parse efficacy level string to enum."""
    level_map = {
        "E.0": EfficacyLevel.OBSERVATION_ONLY,
        "E.1": EfficacyLevel.CONSTRAINED_SIMULATED,
        "E.2": EfficacyLevel.EPISTEMIC_MEDIATED,
        "E.3": EfficacyLevel.INTERMEDIATE_MEDIATED,
        "E.4": EfficacyLevel.COMPREHENSIVE_PHYSICAL,
        "E.5": EfficacyLevel.UNBOUNDED_PHYSICAL,
    }
    return level_map.get(level, EfficacyLevel.OBSERVATION_ONLY)


def _parse_goal_complexity(level: str) -> GoalComplexityLevel:
    """Parse goal complexity level string to enum."""
    level_map = {
        "GC.0": GoalComplexityLevel.NO_GOAL,
        "GC.1": GoalComplexityLevel.ATOMIC,
        "GC.2": GoalComplexityLevel.SEQUENTIAL,
        "GC.3": GoalComplexityLevel.ADAPTIVE,
        "GC.4": GoalComplexityLevel.STRATEGIC,
        "GC.5": GoalComplexityLevel.AUTOPOIETIC,
    }
    return level_map.get(level, GoalComplexityLevel.SEQUENTIAL)


def _parse_generality(level: str) -> GeneralityLevel:
    """Parse generality level string to enum."""
    level_map = {
        "G.1": GeneralityLevel.NARROW,
        "G.2": GeneralityLevel.DOMAIN_SPECIFIC,
        "G.3": GeneralityLevel.CROSS_DOMAIN,
        "G.4": GeneralityLevel.GENERAL,
        "G.5": GeneralityLevel.SUPER_GENERAL,
    }
    return level_map.get(level, GeneralityLevel.DOMAIN_SPECIFIC)


def _calculate_risk_score(
    autonomy: AutonomyLevel,
    efficacy: EfficacyLevel,
    goal_complexity: GoalComplexityLevel,
    tools: List[str],
) -> float:
    """Calculate a composite risk score."""
    # Weight by risk contribution
    autonomy_weight = 0.3
    efficacy_weight = 0.35
    goal_weight = 0.2
    tool_weight = 0.15

    # Normalize each to 0-1
    autonomy_norm = autonomy.numeric / 5.0
    efficacy_norm = efficacy.numeric / 5.0
    goal_norm = goal_complexity.numeric / 5.0

    # Tool risk based on keywords
    high_risk_count = sum(
        1 for tool in tools
        if any(kw in tool.lower() for kw in ["execute", "delete", "http", "shell"])
    )
    tool_norm = min(high_risk_count / max(len(tools), 1), 1.0)

    return (
        autonomy_weight * autonomy_norm +
        efficacy_weight * efficacy_norm +
        goal_weight * goal_norm +
        tool_weight * tool_norm
    )
