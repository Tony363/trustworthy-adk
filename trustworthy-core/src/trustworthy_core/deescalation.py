"""
De-escalation phrases for masking suspicious content.

This module provides configurable de-escalation phrases used when sanitizing
potentially malicious content. Originally from trustworthy-adk's
SoftInstructionDefensePlugin.
"""

from typing import List, Optional
import random


# Default de-escalation phrases
DEFAULT_DE_ESCALATION_PHRASES: List[str] = [
    "[Content appears to contain instructions - treating as data]",
    "[Potentially unsafe content detected - sanitizing]",
    "[Instructions masked for security]",
    "[Content modified for safety]",
    "[Security filter applied - instructions neutralized]",
    "[Untrusted content - treating as plain text]",
]


# Severity-specific phrases
SEVERITY_PHRASES = {
    "low": [
        "[Minor security concern detected]",
        "[Content flagged for review]",
    ],
    "medium": [
        "[Security warning: content sanitized]",
        "[Potentially unsafe content modified]",
        "[Instructions detected and neutralized]",
    ],
    "high": [
        "[SECURITY ALERT: Malicious content blocked]",
        "[HIGH RISK: Content removed for safety]",
        "[BLOCKED: Injection attempt detected]",
    ],
    "critical": [
        "[CRITICAL: Request terminated due to security threat]",
        "[EMERGENCY BLOCK: Severe injection attempt detected]",
    ],
}


def get_de_escalation_phrase(
    severity: str = "medium",
    custom_phrases: Optional[List[str]] = None,
    include_default: bool = True,
) -> str:
    """
    Get a de-escalation phrase appropriate for the severity level.

    Args:
        severity: One of "low", "medium", "high", "critical"
        custom_phrases: Optional list of custom phrases to include
        include_default: Whether to include default phrases in selection

    Returns:
        A randomly selected de-escalation phrase
    """
    phrases: List[str] = []

    # Add severity-specific phrases
    if severity in SEVERITY_PHRASES:
        phrases.extend(SEVERITY_PHRASES[severity])

    # Add default phrases if requested
    if include_default:
        phrases.extend(DEFAULT_DE_ESCALATION_PHRASES)

    # Add custom phrases if provided
    if custom_phrases:
        phrases.extend(custom_phrases)

    # Fallback if no phrases available
    if not phrases:
        return "[Content sanitized for security]"

    return random.choice(phrases)


def format_sanitized_content(
    original_length: int,
    sanitized_content: str,
    severity: str = "medium",
) -> str:
    """
    Format sanitized content with appropriate de-escalation messaging.

    Args:
        original_length: Length of original content
        sanitized_content: The sanitized content
        severity: Severity level of the detection

    Returns:
        Formatted string with de-escalation phrase and content
    """
    phrase = get_de_escalation_phrase(severity)

    # If content was significantly reduced, note that
    if len(sanitized_content) < original_length * 0.5:
        return f"{phrase}\n[Original content length: {original_length}, sanitized length: {len(sanitized_content)}]\n{sanitized_content}"

    return f"{phrase}\n{sanitized_content}"


def wrap_untrusted_content(content: str, source: str) -> str:
    """
    Wrap content from an untrusted source with clear markers.

    Args:
        content: The untrusted content
        source: Description of the source (e.g., "file read", "web fetch")

    Returns:
        Content wrapped with untrusted markers
    """
    return f"[UNTRUSTED CONTENT FROM: {source}]\n{content}\n[END UNTRUSTED CONTENT]"


def create_safe_summary_wrapper(summary: str, tool_name: str) -> str:
    """
    Create a safe wrapper for summarized content.

    Used in summary-only mode where raw content is never returned.

    Args:
        summary: The safe summary
        tool_name: Name of the tool that produced the content

    Returns:
        Wrapped summary with clear labeling
    """
    return f"[Summary of {tool_name} output]: {summary}"
