"""
OutputGuard - IPI (Indirect Prompt Injection) defense for tool outputs.

This module implements the OutputGuard pattern that scans tool outputs
before returning them to the main LLM (Claude). It provides two modes:

1. Sanitize Mode (default): Scans outputs and sanitizes suspicious content
2. Summary-Only Mode: Never returns raw content, always summarizes

Summary-Only Mode is the closest equivalent to trustworthy-adk's
ActionSelectorAgent, which blocks tool results from feeding back to the LLM.

Usage:
    from trustworthy_mcp.policy.output_guard import OutputGuard

    guard = OutputGuard(summary_only_mode=True)
    safe_output = await guard.process_output("read_file", raw_content)
"""

import logging
from dataclasses import dataclass
from typing import Optional, List, Callable, Awaitable

# Import from trustworthy-core (shared logic)
from trustworthy_core.patterns import is_suspicious, get_matched_patterns, calculate_risk_score
from trustworthy_core.deescalation import (
    get_de_escalation_phrase,
    wrap_untrusted_content,
    create_safe_summary_wrapper,
)
from trustworthy_core.rewriter import build_summary_prompt, REWRITER_SYSTEM_PROMPT
from trustworthy_core.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class OutputGuardResult:
    """Result of OutputGuard processing."""

    original_length: int
    processed_output: str
    was_modified: bool
    mode: str  # "sanitize" or "summary"
    risk_score: float = 0.0
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


# Type alias for the scanner function
ScannerFunc = Callable[[str, str], Awaitable[dict]]


class OutputGuard:
    """
    Scans and processes tool outputs before returning to the main LLM.

    Provides IPI (Indirect Prompt Injection) defense by either:
    1. Sanitizing suspicious content (default)
    2. Summarizing all content (summary-only mode for maximum security)

    The summary-only mode is equivalent to the ActionSelectorAgent pattern
    from trustworthy-adk - it prevents raw tool output from ever reaching
    the main LLM's context.
    """

    def __init__(
        self,
        scanner: Optional[ScannerFunc] = None,
        scanner_model: str = "claude-3-haiku",
        summary_only_mode: bool = False,
        summary_max_length: int = 500,
        risk_threshold: float = 0.7,
        untrusted_paths: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the OutputGuard.

        Args:
            scanner: Optional async function for LLM-based scanning.
                     Signature: async (content, context) -> {"is_injection": bool, "summary": str}
            scanner_model: Model to use if no scanner provided
            summary_only_mode: If True, NEVER return raw content - always summarize
            summary_max_length: Maximum length of summaries
            risk_threshold: Risk score threshold for triggering sanitization
            untrusted_paths: File paths that should always be treated as untrusted
        """
        self.scanner = scanner
        self.scanner_model = scanner_model
        self.summary_only_mode = summary_only_mode
        self.summary_max_length = summary_max_length
        self.risk_threshold = risk_threshold
        self.untrusted_paths = untrusted_paths or [
            ".git",
            "node_modules",
            "vendor",
            "__pycache__",
            ".env",
        ]

        # Load config overrides
        config = get_config()
        if config.summary_only_mode:
            self.summary_only_mode = True
        if config.summary_max_length:
            self.summary_max_length = config.summary_max_length

    async def process_output(
        self,
        tool_name: str,
        raw_output: str,
        context: Optional[str] = None,
    ) -> OutputGuardResult:
        """
        Process tool output for safety.

        This is the main entry point. Based on configuration, it either:
        - Summary-only mode: Always summarizes (maximum IPI protection)
        - Sanitize mode: Scans and sanitizes only if threats detected

        Args:
            tool_name: Name of the tool that produced the output
            raw_output: Raw output from the tool
            context: Optional context (e.g., file path, URL)

        Returns:
            OutputGuardResult with processed output
        """
        if self.summary_only_mode:
            return await self._process_summary_only(tool_name, raw_output, context)
        else:
            return await self._process_with_sanitization(tool_name, raw_output, context)

    async def _process_summary_only(
        self,
        tool_name: str,
        raw_output: str,
        context: Optional[str] = None,
    ) -> OutputGuardResult:
        """
        Process in summary-only mode - never return raw content.

        This provides the closest equivalent to ActionSelectorAgent's
        feedback-blocking behavior.
        """
        logger.info(f"OutputGuard: Processing {tool_name} in summary-only mode")

        # Always create a safe summary
        summary = await self._create_safe_summary(tool_name, raw_output, context)

        return OutputGuardResult(
            original_length=len(raw_output),
            processed_output=summary,
            was_modified=True,
            mode="summary",
            risk_score=0.0,  # We don't need to calculate - we always summarize
            warnings=["Summary-only mode: raw content not returned"],
        )

    async def _process_with_sanitization(
        self,
        tool_name: str,
        raw_output: str,
        context: Optional[str] = None,
    ) -> OutputGuardResult:
        """
        Process with sanitization - scan and sanitize if threats detected.
        """
        warnings: List[str] = []
        detected_risk_score: float = 0.0

        # Step 1: Fast heuristic check
        if is_suspicious(raw_output):
            matches = get_matched_patterns(raw_output)
            detected_risk_score = calculate_risk_score(raw_output)

            warnings.append(f"Heuristic detection: {len(matches)} suspicious pattern(s)")
            logger.warning(f"OutputGuard: Suspicious patterns detected in {tool_name}")

            # If above threshold, sanitize
            if detected_risk_score >= self.risk_threshold:
                return await self._sanitize_output(
                    tool_name, raw_output, context, detected_risk_score, warnings
                )

        # Step 2: Deep LLM scan if scanner available
        if self.scanner:
            scan_result = await self.scanner(raw_output, context or tool_name)

            if scan_result.get("is_injection", False):
                detected_risk_score = scan_result.get("risk_score", 0.9)
                warnings.append(f"LLM detection: {scan_result.get('explanation', 'injection detected')}")

                return await self._sanitize_output(
                    tool_name, raw_output, context, detected_risk_score, warnings
                )

        # Step 3: Check if from untrusted path
        if context and self._is_untrusted_path(context):
            warnings.append(f"Content from untrusted path: {context}")
            # Wrap but don't sanitize
            wrapped = wrap_untrusted_content(raw_output, context)
            return OutputGuardResult(
                original_length=len(raw_output),
                processed_output=wrapped,
                was_modified=True,
                mode="sanitize",
                risk_score=max(detected_risk_score, 0.3),
                warnings=warnings,
            )

        # Return original with any detected risk score
        return OutputGuardResult(
            original_length=len(raw_output),
            processed_output=raw_output,
            was_modified=False,
            mode="sanitize",
            risk_score=detected_risk_score,
            warnings=warnings if warnings else None,
        )

    async def _sanitize_output(
        self,
        tool_name: str,
        content: str,
        context: Optional[str],
        risk_score: float,
        warnings: List[str],
    ) -> OutputGuardResult:
        """
        Sanitize suspicious output.

        For high-risk content, we create a safe summary instead of
        trying to remove specific patterns (which could be bypassed).
        """
        logger.warning(f"OutputGuard: Sanitizing {tool_name} output (risk={risk_score:.2f})")

        # For high risk, just summarize
        if risk_score >= 0.8:
            summary = await self._create_safe_summary(tool_name, content, context)
            severity = "critical" if risk_score >= 0.95 else "high"
            phrase = get_de_escalation_phrase(severity)

            return OutputGuardResult(
                original_length=len(content),
                processed_output=f"{phrase}\n\n{summary}",
                was_modified=True,
                mode="sanitize",
                risk_score=risk_score,
                warnings=warnings + ["High-risk content summarized for safety"],
            )

        # For medium risk, try to preserve with warning
        phrase = get_de_escalation_phrase("medium")
        wrapped = wrap_untrusted_content(content, f"{tool_name} (sanitized)")

        return OutputGuardResult(
            original_length=len(content),
            processed_output=f"{phrase}\n\n{wrapped}",
            was_modified=True,
            mode="sanitize",
            risk_score=risk_score,
            warnings=warnings,
        )

    async def _create_safe_summary(
        self,
        tool_name: str,
        content: str,
        context: Optional[str] = None,
    ) -> str:
        """
        Create a safe summary of content.

        Uses LLM if scanner available, otherwise creates a basic summary.
        """
        if self.scanner:
            # Use LLM to create summary
            prompt = build_summary_prompt(content, self.summary_max_length)
            try:
                result = await self.scanner(prompt, "summary_request")
                summary = result.get("summary", "")
                if summary:
                    return create_safe_summary_wrapper(summary, tool_name)
            except Exception as e:
                logger.error(f"LLM summary failed: {e}")

        # Fallback: basic summary
        return self._create_basic_summary(tool_name, content, context)

    def _create_basic_summary(
        self,
        tool_name: str,
        content: str,
        context: Optional[str] = None,
    ) -> str:
        """Create a basic summary without LLM.

        For security reasons, this summary does NOT include any raw content.
        This ensures IPI attacks cannot pass through even in summary form.
        """
        # Count basic metrics only - no raw content
        lines = content.split("\n")
        words = len(content.split())
        chars = len(content)
        line_count = len(lines)

        summary_parts = [
            f"Content from {tool_name}",
            f"Size: {chars} characters, {words} words, {line_count} lines",
        ]

        if context:
            summary_parts.append(f"Source: {context}")

        # For security: Do NOT include any raw content or preview
        # This prevents injection attacks from passing through summaries

        return create_safe_summary_wrapper("\n".join(summary_parts), tool_name)

    def _is_untrusted_path(self, path: str) -> bool:
        """Check if a path should be treated as untrusted."""
        path_lower = path.lower()
        return any(
            untrusted in path_lower
            for untrusted in self.untrusted_paths
        )


# Convenience functions for integration

async def guard_output(
    tool_name: str,
    output: str,
    context: Optional[str] = None,
    summary_only: bool = False,
) -> str:
    """
    Convenience function to guard tool output.

    Args:
        tool_name: Name of the tool
        output: Raw output
        context: Optional context
        summary_only: Force summary-only mode

    Returns:
        Safe output string
    """
    guard = OutputGuard(summary_only_mode=summary_only)
    result = await guard.process_output(tool_name, output, context)
    return result.processed_output


def should_tag_as_untrusted(tool_name: str, context: Optional[str] = None) -> bool:
    """
    Check if output from a tool/context should be tagged as untrusted.

    Args:
        tool_name: Name of the tool
        context: Optional context (path, URL, etc.)

    Returns:
        True if output should be tagged as untrusted
    """
    # Tools that fetch external content
    external_tools = {"http_request", "fetch_url", "web_fetch", "execute_command"}

    if tool_name in external_tools:
        return True

    # Check context for untrusted paths
    if context:
        guard = OutputGuard()
        return guard._is_untrusted_path(context)

    return False
