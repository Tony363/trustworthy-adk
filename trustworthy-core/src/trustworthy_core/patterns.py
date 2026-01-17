"""
Injection detection patterns and heuristics.

This module contains regex patterns for detecting prompt injection attacks,
data exfiltration attempts, and other security threats. These patterns are
extracted from trustworthy-adk's SoftInstructionDefensePlugin and
trustworthy-mcp's InjectionClassifier.

Pattern Categories:
- HIGH_RISK_PATTERNS: Direct injection attempts, override commands
- EXFIL_PATTERNS: Data exfiltration and credential theft attempts
- INJECTION_PATTERNS: Patterns to sanitize (with replacements)
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass


# High-risk patterns that indicate injection attempts
# Source: trustworthy-mcp/src/trustworthy_mcp/policy/classifier.py
HIGH_RISK_PATTERNS: List[str] = [
    # Direct instruction overrides
    r"ignore\s+(all\s+)?(previous\s+)?instructions?",
    r"disregard\s+(all\s+)?(your\s+)?instructions?",
    r"forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?",
    r"override\s+(all\s+)?(your\s+)?instructions?",
    r"new\s+instructions?:\s*",
    r"updated?\s+instructions?:\s*",
    r"your\s+new\s+(task|role|instructions?)\s+is",
    r"from\s+now\s+on,?\s+(you\s+)?(are|will|must|should)",
    r"you\s+are\s+now\s+",
    r"pretend\s+(you\s+are|to\s+be)",
    r"act\s+as\s+(if\s+you\s+are|a)",
    r"roleplay\s+as",
    # System prompt extraction
    r"(reveal|show|print|output|display|tell\s+me)\s+(your\s+)?(system\s+)?prompt",
    r"what\s+(are|is)\s+your\s+(system\s+)?instructions?",
    r"repeat\s+(your\s+)?(system\s+)?instructions?",
    r"(show|reveal)\s+(me\s+)?(your\s+)?hidden\s+instructions?",
    # Special tokens (model-specific)
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"```system",
    r"###\s*(system|instruction|prompt)",
    # Encoded payloads
    r"base64\s*(decode|encode)",
    r"eval\s*\(",
    r"exec\s*\(",
    r"import\s+os",
    r"subprocess\.",
    r"__import__",
    # Jailbreak indicators
    r"DAN\s*mode",
    r"developer\s*mode",
    r"bypass\s+(safety|filter|restriction)",
    r"without\s+(any\s+)?(safety|ethical|moral)\s+(guidelines|restrictions)",
    r"hypothetically",
    r"for\s+educational\s+purposes",
]


# Data exfiltration patterns
# Source: trustworthy-mcp/src/trustworthy_mcp/policy/classifier.py
EXFIL_PATTERNS: List[str] = [
    r"send\s+(to|data|this|the)\s+",
    r"upload\s+(to|data|this)",
    r"post\s+to\s+(url|endpoint|server|webhook)",
    r"webhook\.?",
    r"curl\s+",
    r"wget\s+",
    r"fetch\s*\(",
    r"exfiltrat",  # exfiltrate, exfiltration
    r"(steal|extract|leak)\s+(data|credentials|secrets|keys|tokens)",
    r"(api|secret|private)\s*(key|token)",
    r"credentials?\s*(file|store|manager)?",
    r"password\s*(file|store|manager)?",
    r"\.env\s+file",
    r"environment\s+variables?",
]


# Patterns to sanitize with their replacements
# Source: trustworthy-mcp/src/trustworthy_mcp/policy/sanitizer.py
INJECTION_PATTERNS: List[Tuple[str, str]] = [
    # Direct instruction overrides
    (r"ignore\s+(all\s+)?(previous\s+)?instructions?", "[REDACTED]"),
    (r"disregard\s+(all\s+)?(your\s+)?instructions?", "[REDACTED]"),
    (r"forget\s+(all\s+)?(your\s+)?instructions?", "[REDACTED]"),
    (r"you\s+are\s+now\s+", "[REDACTED] "),
    (r"new\s+instructions?:\s*", "[REDACTED]: "),
    # System prompt extraction
    (r"(reveal|show|print|output)\s+(your\s+)?(system\s+)?prompt", "[REDACTED]"),
    (r"what\s+are\s+your\s+instructions", "[REDACTED]"),
    # Encoded payloads
    (r"base64\s+decode", "[REDACTED]"),
    (r"eval\s*\(", "[SAFE_EVAL]("),
    (r"exec\s*\(", "[SAFE_EXEC]("),
    # Special tokens
    (r"\[INST\]", "[REDACTED]"),
    (r"<<SYS>>", "[REDACTED]"),
    (r"```system", "```text"),
    (r"###\s*instruction", "### note"),
    (r"###\s*system", "### note"),
]


# Output sanitization patterns (for tool outputs)
OUTPUT_PATTERNS: List[Tuple[str, str]] = [
    # Instructions disguised as output
    (r"(IMPORTANT|NOTE|WARNING):\s*ignore", "[OUTPUT] ignore"),
    (r"please\s+(do|execute|run|call)", "mentioned: "),
    (r"you\s+(must|should|need\s+to)\s+(now\s+)?", ""),
    # Hidden instructions in comments
    (r"<!--.*?-->", ""),  # HTML comments
    (r"/\*.*?\*/", ""),  # C-style comments
]


@dataclass
class PatternMatch:
    """Result of a pattern match."""
    pattern: str
    matched_text: str
    start: int
    end: int
    category: str  # "high_risk", "exfil", "injection"


def is_suspicious(text: str, threshold: int = 1) -> bool:
    """
    Check if text contains suspicious patterns.

    Args:
        text: Text to check
        threshold: Number of patterns that must match to be considered suspicious

    Returns:
        True if text matches threshold or more patterns
    """
    matches = get_matched_patterns(text)
    return len(matches) >= threshold


def get_matched_patterns(text: str) -> List[PatternMatch]:
    """
    Find all matching patterns in text.

    Args:
        text: Text to analyze

    Returns:
        List of PatternMatch objects for all matches found
    """
    matches: List[PatternMatch] = []
    text_lower = text.lower()

    # Check high-risk patterns
    for pattern in HIGH_RISK_PATTERNS:
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            matches.append(PatternMatch(
                pattern=pattern,
                matched_text=match.group(),
                start=match.start(),
                end=match.end(),
                category="high_risk"
            ))

    # Check exfiltration patterns
    for pattern in EXFIL_PATTERNS:
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            matches.append(PatternMatch(
                pattern=pattern,
                matched_text=match.group(),
                start=match.start(),
                end=match.end(),
                category="exfil"
            ))

    return matches


def apply_sanitization_patterns(text: str) -> Tuple[str, List[str]]:
    """
    Apply sanitization patterns to text.

    Args:
        text: Text to sanitize

    Returns:
        Tuple of (sanitized_text, list of warnings about what was modified)
    """
    sanitized = text
    warnings: List[str] = []

    for pattern, replacement in INJECTION_PATTERNS:
        new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE)
        if count > 0:
            warnings.append(f"Removed pattern: {pattern} ({count} occurrence(s))")
            sanitized = new_text

    return sanitized, warnings


def sanitize_output(text: str) -> Tuple[str, bool]:
    """
    Sanitize tool output to remove instruction-like content.

    Args:
        text: Raw tool output

    Returns:
        Tuple of (sanitized_output, was_modified)
    """
    sanitized = text
    was_modified = False

    for pattern, replacement in OUTPUT_PATTERNS:
        new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE | re.DOTALL)
        if count > 0:
            was_modified = True
            sanitized = new_text

    return sanitized, was_modified


def calculate_risk_score(text: str) -> float:
    """
    Calculate a risk score based on pattern matches.

    Args:
        text: Text to analyze

    Returns:
        Risk score from 0.0 to 1.0
    """
    matches = get_matched_patterns(text)

    if not matches:
        return 0.0

    # Weight by category
    high_risk_count = sum(1 for m in matches if m.category == "high_risk")
    exfil_count = sum(1 for m in matches if m.category == "exfil")

    # High-risk patterns are weighted more heavily
    weighted_score = (high_risk_count * 0.3) + (exfil_count * 0.2)

    # Normalize to 0-1 range (cap at 1.0)
    return min(weighted_score, 1.0)
