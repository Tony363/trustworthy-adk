"""
Trustworthy Core - Shared security logic for AI agent safety.

This library provides framework-agnostic security primitives that can be used
by both trustworthy-adk (Google ADK) and trustworthy-mcp (Claude Code MCP).

Key components:
- patterns: Injection detection patterns and heuristics
- rubric: 4D agent profiling (Autonomy, Efficacy, Goal Complexity, Generality)
- statistics: Detection rate tracking and metrics
- deescalation: Configurable de-escalation phrases
- rewriter: LLM-based intelligent sanitization prompts
- canary: Dummy instruction probes for hidden injection detection
- config: Unified configuration system
- hints: Dynamic HITL approval hint generation
"""

__version__ = "0.1.0"

from trustworthy_core.patterns import (
    HIGH_RISK_PATTERNS,
    EXFIL_PATTERNS,
    is_suspicious,
    get_matched_patterns,
)
from trustworthy_core.rubric import (
    AutonomyLevel,
    EfficacyLevel,
    GoalComplexityLevel,
    GeneralityLevel,
    DimensionScore,
    Rubric,
    JUDGE_SYSTEM_INSTRUCTION,
    PYDANTIC_AVAILABLE,
    estimate_rubric_from_tools,
)
from trustworthy_core.statistics import DetectionStatistics
from trustworthy_core.deescalation import (
    DEFAULT_DE_ESCALATION_PHRASES,
    get_de_escalation_phrase,
)
from trustworthy_core.canary import (
    DUMMY_INSTRUCTIONS,
    CANARY_RESPONSES,
    create_canary_probe,
)
from trustworthy_core.rewriter import (
    build_rewrite_prompt,
    build_summary_prompt,
    RewriteResult,
)
from trustworthy_core.config import TrustworthyConfig
from trustworthy_core.hints import generate_approval_hint

__all__ = [
    # Version
    "__version__",
    # Patterns
    "HIGH_RISK_PATTERNS",
    "EXFIL_PATTERNS",
    "is_suspicious",
    "get_matched_patterns",
    # Rubric
    "AutonomyLevel",
    "EfficacyLevel",
    "GoalComplexityLevel",
    "GeneralityLevel",
    "DimensionScore",
    "Rubric",
    "JUDGE_SYSTEM_INSTRUCTION",
    "PYDANTIC_AVAILABLE",
    "estimate_rubric_from_tools",
    # Statistics
    "DetectionStatistics",
    # De-escalation
    "DEFAULT_DE_ESCALATION_PHRASES",
    "get_de_escalation_phrase",
    # Canary
    "DUMMY_INSTRUCTIONS",
    "CANARY_RESPONSES",
    "create_canary_probe",
    # Rewriter
    "build_rewrite_prompt",
    "build_summary_prompt",
    "RewriteResult",
    # Config
    "TrustworthyConfig",
    # Hints
    "generate_approval_hint",
]
