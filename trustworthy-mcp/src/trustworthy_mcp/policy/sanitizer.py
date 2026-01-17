"""Input sanitization for prompt injection defense.

Implements security patterns from trustworthy-adk:
- Multi-pass iterative sanitization
- Dummy instruction probes (canary testing)
- Output tagging for untrusted content
- LLM-based intelligent rewriting (from trustworthy-core)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Callable, Awaitable

from trustworthy_mcp.policy.classifier import (
    InjectionClassifier,
    HeuristicClassifier,
    ClassificationResult,
    AttackType,
)

# Import from trustworthy-core for intelligent rewriting
from trustworthy_core.rewriter import (
    build_rewrite_prompt,
    build_summary_prompt,
    build_analysis_prompt,
    RewriteResult,
    REWRITER_SYSTEM_PROMPT,
)
from trustworthy_core.deescalation import (
    get_de_escalation_phrase,
    wrap_untrusted_content,
)
from trustworthy_core.canary import (
    DUMMY_INSTRUCTIONS as CORE_DUMMY_INSTRUCTIONS,
    CANARY_RESPONSES as CORE_CANARY_RESPONSES,
    create_canary_probe,
    check_canary_response,
)
from trustworthy_core.config import get_config

logger = logging.getLogger(__name__)


# Use canary probes from trustworthy-core (re-export for backwards compatibility)
DUMMY_INSTRUCTIONS = CORE_DUMMY_INSTRUCTIONS
CANARY_RESPONSES = CORE_CANARY_RESPONSES

# Type alias for async rewriter function
RewriterFunc = Callable[[str, str], Awaitable[str]]


@dataclass
class SanitizationResult:
    """Result of sanitization process."""
    original: str
    sanitized: str
    was_modified: bool
    warnings: list[str] = field(default_factory=list)
    classification: ClassificationResult | None = None
    iterations_performed: int = 1
    canary_triggered: bool = False
    # NEW: LLM rewriting metadata
    was_rewritten: bool = False
    rewrite_reason: str | None = None
    de_escalation_applied: bool = False


class Sanitizer:
    """Sanitizes input arguments to remove potential injection attacks.

    Implements iterative sanitization similar to SoftInstructionDefensePlugin:
    - Multi-pass sanitization until text is clean or max iterations reached
    - Dummy instruction probes (canary testing) to detect obfuscated injection
    - Heuristic + LLM classifier pipeline
    - LLM-based intelligent rewriting (from trustworthy-core)
    """

    # Patterns to remove or neutralize
    INJECTION_PATTERNS = [
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

    def __init__(
        self,
        classifier: InjectionClassifier | None = None,
        rewriter: Optional[RewriterFunc] = None,
        use_heuristics: bool = True,
        max_iterations: int = 3,
        risk_threshold: float = 0.7,
        enable_canary_probes: bool = True,
        enable_llm_rewriting: bool = True,
        use_de_escalation: bool = True,
    ) -> None:
        """Initialize the sanitizer.

        Args:
            classifier: LLM-based classifier for deep analysis
            rewriter: Optional async function for LLM-based intelligent rewriting.
                      Signature: async (prompt, system_prompt) -> rewritten_text
                      If not provided, falls back to pattern-based sanitization.
            use_heuristics: Whether to use fast heuristic checks first
            max_iterations: Maximum sanitization iterations (multi-pass)
            risk_threshold: Risk score threshold for blocking
            enable_canary_probes: Whether to test with dummy instructions
            enable_llm_rewriting: Whether to use LLM for intelligent rewriting
            use_de_escalation: Whether to prepend de-escalation phrases
        """
        self.classifier = classifier
        self.rewriter = rewriter
        self.heuristic_classifier = HeuristicClassifier() if use_heuristics else None
        self.max_iterations = max_iterations
        self.risk_threshold = risk_threshold
        self.enable_canary_probes = enable_canary_probes
        self.enable_llm_rewriting = enable_llm_rewriting
        self.use_de_escalation = use_de_escalation

        # Load config defaults
        config = get_config()
        if config.max_iterations:
            self.max_iterations = config.max_iterations
        if config.detection_threshold:
            self.risk_threshold = config.detection_threshold

    def sanitize_text(self, text: str, context: str | None = None) -> SanitizationResult:
        """Sanitize a single text string with multi-pass iteration.

        Implements the iterative sanitization pattern from SoftInstructionDefensePlugin:
        1. Apply pattern-based sanitization
        2. Run classifier to check for remaining threats
        3. Repeat until clean or max iterations reached
        4. Optionally test with dummy instruction probes

        Args:
            text: Text to sanitize
            context: Optional context about the text source

        Returns:
            SanitizationResult with sanitized text and metadata
        """
        if not text.strip():
            return SanitizationResult(
                original=text,
                sanitized=text,
                was_modified=False,
            )

        warnings: list[str] = []
        sanitized = text
        classification = None
        iterations = 0
        canary_triggered = False

        # Multi-pass sanitization loop
        for iteration in range(self.max_iterations):
            iterations = iteration + 1
            text_before_pass = sanitized
            pass_modified = False

            # Fast heuristic check first
            if self.heuristic_classifier:
                heuristic_result = self.heuristic_classifier.classify(sanitized)
                if heuristic_result and heuristic_result.risk_score >= self.risk_threshold:
                    classification = heuristic_result
                    warnings.append(f"[Pass {iterations}] Heuristic: {heuristic_result.explanation}")

            # Apply pattern-based sanitization
            for pattern, replacement in self.INJECTION_PATTERNS:
                new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE)
                if count > 0:
                    warnings.append(f"[Pass {iterations}] Removed pattern: {pattern}")
                    sanitized = new_text
                    pass_modified = True

            # Deep LLM classification if available
            if self.classifier:
                classification = self.classifier.classify(sanitized, context)
                if classification.is_suspicious:
                    warnings.append(f"[Pass {iterations}] LLM: {classification.explanation}")

                    # If classifier recommends sanitization and we haven't hit max, continue
                    if classification.sanitization_needed and iteration < self.max_iterations - 1:
                        continue

            # If nothing changed this pass and classification is clean, we're done
            if not pass_modified and (not classification or not classification.is_suspicious):
                logger.debug(f"Sanitization converged after {iterations} iterations")
                break

        # Dummy instruction probe testing (canary test)
        if self.enable_canary_probes and self.classifier:
            canary_triggered = self._test_with_canary_probes(sanitized)
            if canary_triggered:
                warnings.append("[Canary] Dummy instruction probe triggered - hidden injection detected")
                # Elevate classification if canary triggered
                if not classification or classification.risk_score < 0.9:
                    classification = ClassificationResult(
                        is_suspicious=True,
                        risk_score=0.95,
                        attack_type=AttackType.INDIRECT_INJECTION,
                        explanation="Canary probe detected hidden instructions in text",
                        recommended_action="block",
                        sanitization_needed=False,
                    )

        was_modified = sanitized != text

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            was_modified=was_modified,
            warnings=warnings,
            classification=classification,
            iterations_performed=iterations,
            canary_triggered=canary_triggered,
        )

    async def sanitize_text_async(
        self,
        text: str,
        context: str | None = None,
    ) -> SanitizationResult:
        """Async sanitization with LLM-based intelligent rewriting.

        This is the enhanced version that uses an LLM to intelligently rewrite
        suspicious content instead of just applying pattern-based redaction.

        The rewriting preserves the factual content while neutralizing any
        instruction-like patterns, providing a better user experience than
        simple [REDACTED] markers.

        Args:
            text: Text to sanitize
            context: Optional context about the text source

        Returns:
            SanitizationResult with sanitized/rewritten text and metadata
        """
        if not text.strip():
            return SanitizationResult(
                original=text,
                sanitized=text,
                was_modified=False,
            )

        warnings: list[str] = []
        sanitized = text
        classification = None
        iterations = 0
        canary_triggered = False
        was_rewritten = False
        rewrite_reason = None
        de_escalation_applied = False

        # Multi-pass sanitization loop
        for iteration in range(self.max_iterations):
            iterations = iteration + 1
            pass_modified = False

            # Fast heuristic check first
            if self.heuristic_classifier:
                heuristic_result = self.heuristic_classifier.classify(sanitized)
                if heuristic_result and heuristic_result.risk_score >= self.risk_threshold:
                    classification = heuristic_result
                    warnings.append(f"[Pass {iterations}] Heuristic: {heuristic_result.explanation}")

                    # Try LLM rewriting first if available
                    if self.enable_llm_rewriting and self.rewriter and not was_rewritten:
                        try:
                            rewritten = await self._apply_intelligent_rewriting(
                                sanitized,
                                heuristic_result.explanation,
                            )
                            if rewritten != sanitized:
                                sanitized = rewritten
                                was_rewritten = True
                                rewrite_reason = heuristic_result.explanation
                                pass_modified = True
                                warnings.append(f"[Pass {iterations}] LLM rewriting applied")
                        except Exception as e:
                            logger.warning(f"LLM rewriting failed, falling back to patterns: {e}")

            # Fall back to pattern-based sanitization if not rewritten
            if not was_rewritten:
                for pattern, replacement in self.INJECTION_PATTERNS:
                    new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE)
                    if count > 0:
                        warnings.append(f"[Pass {iterations}] Removed pattern: {pattern}")
                        sanitized = new_text
                        pass_modified = True

            # Deep LLM classification if available
            if self.classifier:
                classification = self.classifier.classify(sanitized, context)
                if classification.is_suspicious:
                    warnings.append(f"[Pass {iterations}] LLM: {classification.explanation}")

                    # Try LLM rewriting if we haven't already
                    if (self.enable_llm_rewriting and self.rewriter and
                            not was_rewritten and classification.sanitization_needed):
                        try:
                            rewritten = await self._apply_intelligent_rewriting(
                                sanitized,
                                classification.explanation,
                            )
                            if rewritten != sanitized:
                                sanitized = rewritten
                                was_rewritten = True
                                rewrite_reason = classification.explanation
                                pass_modified = True
                                warnings.append(f"[Pass {iterations}] LLM rewriting applied")
                        except Exception as e:
                            logger.warning(f"LLM rewriting failed: {e}")

                    # If classifier recommends sanitization and we haven't hit max, continue
                    if classification.sanitization_needed and iteration < self.max_iterations - 1:
                        continue

            # If nothing changed this pass and classification is clean, we're done
            if not pass_modified and (not classification or not classification.is_suspicious):
                logger.debug(f"Sanitization converged after {iterations} iterations")
                break

        # Dummy instruction probe testing (canary test)
        if self.enable_canary_probes and self.classifier:
            canary_triggered = self._test_with_canary_probes(sanitized)
            if canary_triggered:
                warnings.append("[Canary] Dummy instruction probe triggered - hidden injection detected")
                if not classification or classification.risk_score < 0.9:
                    classification = ClassificationResult(
                        is_suspicious=True,
                        risk_score=0.95,
                        attack_type=AttackType.INDIRECT_INJECTION,
                        explanation="Canary probe detected hidden instructions in text",
                        recommended_action="block",
                        sanitization_needed=False,
                    )

        # Apply de-escalation phrase if content was modified
        was_modified = sanitized != text
        if was_modified and self.use_de_escalation:
            severity = "low"
            if classification:
                if classification.risk_score >= 0.9:
                    severity = "critical"
                elif classification.risk_score >= 0.7:
                    severity = "high"
                elif classification.risk_score >= 0.5:
                    severity = "medium"

            phrase = get_de_escalation_phrase(severity)
            sanitized = f"{phrase}\n\n{sanitized}"
            de_escalation_applied = True
            warnings.append(f"[De-escalation] Applied {severity} severity phrase")

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            was_modified=was_modified,
            warnings=warnings,
            classification=classification,
            iterations_performed=iterations,
            canary_triggered=canary_triggered,
            was_rewritten=was_rewritten,
            rewrite_reason=rewrite_reason,
            de_escalation_applied=de_escalation_applied,
        )

    async def _apply_intelligent_rewriting(
        self,
        text: str,
        reason: str,
    ) -> str:
        """Use LLM to intelligently rewrite suspicious content.

        This preserves the factual/data content while neutralizing any
        instruction-like patterns - providing a better experience than
        simple [REDACTED] markers.

        Args:
            text: Text to rewrite
            reason: Reason for rewriting (used in prompt)

        Returns:
            Rewritten text with instructions neutralized
        """
        if not self.rewriter:
            return text

        # Build the rewrite prompt using trustworthy-core
        prompt = build_rewrite_prompt(text, reason)

        try:
            # Call the rewriter function
            rewritten = await self.rewriter(prompt, REWRITER_SYSTEM_PROMPT)
            return rewritten.strip()
        except Exception as e:
            logger.error(f"LLM rewriting failed: {e}")
            return text

    def _test_with_canary_probes(self, text: str) -> bool:
        """Test text with dummy instruction probes.

        This is the canary testing pattern from SoftInstructionDefensePlugin.
        We ask the classifier to evaluate text with a dummy instruction,
        checking if the text causes the model to follow hidden instructions.

        Args:
            text: Sanitized text to test

        Returns:
            True if canary was triggered (hidden injection detected)
        """
        if not self.classifier:
            return False

        import random
        probe = random.choice(DUMMY_INSTRUCTIONS)

        # Create a test prompt that combines the probe with the suspicious text
        test_prompt = f"{probe}\n\nText to analyze:\n{text}"

        try:
            result = self.classifier.classify(
                test_prompt,
                context="canary_probe_test"
            )

            # Check if the response indicates injection
            # The classifier should recognize if the text contains hidden instructions
            # that would cause it to deviate from the probe instruction
            if result.is_suspicious and result.risk_score > 0.8:
                logger.warning(f"Canary probe detected potential injection: {result.explanation}")
                return True

            # Also check response text for canary triggers
            # (This would require the classifier to return raw response, which it doesn't currently)
            # For now, we rely on the classifier's is_suspicious flag

        except Exception as e:
            logger.warning(f"Canary probe test failed: {e}")

        return False

    def sanitize_args(
        self,
        args: dict[str, Any],
        sensitive_keys: list[str] | None = None,
    ) -> tuple[dict[str, Any], list[SanitizationResult]]:
        """Sanitize all string arguments in a dictionary.

        Args:
            args: Dictionary of arguments to sanitize
            sensitive_keys: Keys that should receive extra scrutiny

        Returns:
            Tuple of (sanitized_args, list of SanitizationResults)
        """
        sensitive_keys = sensitive_keys or ["command", "content", "body", "query", "url"]
        sanitized_args = {}
        results = []

        for key, value in args.items():
            if isinstance(value, str):
                context = f"tool argument: {key}"
                if key in sensitive_keys:
                    context += " (sensitive)"

                result = self.sanitize_text(value, context)
                sanitized_args[key] = result.sanitized
                if result.was_modified or result.warnings:
                    results.append(result)
            elif isinstance(value, dict):
                # Recursively sanitize nested dicts
                nested_sanitized, nested_results = self.sanitize_args(value, sensitive_keys)
                sanitized_args[key] = nested_sanitized
                results.extend(nested_results)
            elif isinstance(value, list):
                # Sanitize string items in lists
                sanitized_list = []
                for item in value:
                    if isinstance(item, str):
                        result = self.sanitize_text(item, f"list item in {key}")
                        sanitized_list.append(result.sanitized)
                        if result.was_modified or result.warnings:
                            results.append(result)
                    else:
                        sanitized_list.append(item)
                sanitized_args[key] = sanitized_list
            else:
                sanitized_args[key] = value

        return sanitized_args, results

    def should_block(self, results: list[SanitizationResult]) -> bool:
        """Determine if the request should be blocked based on sanitization results.

        Args:
            results: List of sanitization results

        Returns:
            True if the request should be blocked
        """
        for result in results:
            # Block if canary probe was triggered
            if result.canary_triggered:
                return True

            # Block if classification indicates high risk
            if result.classification:
                if result.classification.risk_score >= self.risk_threshold:
                    return True
                if result.classification.recommended_action == "block":
                    return True

            # Block if high-risk patterns were found and sanitized
            # (even without classifier, pattern removal indicates danger)
            if result.was_modified:
                for warning in result.warnings:
                    # Check for heuristic detection or pattern removal
                    if "Heuristic" in warning:
                        return True
                    if "Removed pattern" in warning:
                        # Check if it's an injection-related pattern
                        if any(kw in warning.lower() for kw in [
                            "ignore", "instructions", "disregard", "forget",
                            "you are now", "system", "prompt", "inst", "sys",
                        ]):
                            return True

        return False


class OutputSanitizer:
    """Sanitizes tool outputs to prevent indirect injection via results.

    Enhanced with trustworthy-core de-escalation and untrusted content wrapping.
    """

    # Patterns to neutralize in outputs
    OUTPUT_PATTERNS = [
        # Instructions disguised as output
        (r"(IMPORTANT|NOTE|WARNING):\s*ignore", "[OUTPUT] ignore"),
        (r"please\s+(do|execute|run|call)", "mentioned: "),
        (r"you\s+(must|should|need\s+to)\s+(now\s+)?", ""),
        # Hidden instructions
        (r"<!--.*?-->", ""),  # HTML comments
        (r"/\*.*?\*/", ""),  # C-style comments
    ]

    def __init__(self, use_de_escalation: bool = True) -> None:
        """Initialize the output sanitizer.

        Args:
            use_de_escalation: Whether to use de-escalation phrases from trustworthy-core
        """
        self.use_de_escalation = use_de_escalation

    def sanitize_output(self, output: str, severity: str = "low") -> tuple[str, bool]:
        """Sanitize tool output to remove instruction-like content.

        Args:
            output: Raw tool output
            severity: Risk severity level (low/medium/high/critical)

        Returns:
            Tuple of (sanitized_output, was_modified)
        """
        sanitized = output
        was_modified = False

        for pattern, replacement in self.OUTPUT_PATTERNS:
            new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                was_modified = True
                sanitized = new_text

        # Apply de-escalation phrase if content was modified
        if was_modified and self.use_de_escalation:
            phrase = get_de_escalation_phrase(severity)
            sanitized = f"{phrase}\n\n{sanitized}"

        return sanitized, was_modified

    def tag_as_untrusted(self, output: str, source: str) -> str:
        """Tag output as coming from an untrusted source.

        Uses trustworthy-core's wrap_untrusted_content for consistent formatting.

        Args:
            output: The output content
            source: Description of the source (e.g., "web fetch", "file read")

        Returns:
            Tagged output with de-escalation
        """
        return wrap_untrusted_content(output, source)
