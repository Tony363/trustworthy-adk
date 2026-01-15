"""Input sanitization for prompt injection defense."""

import re
import logging
from dataclasses import dataclass, field
from typing import Any

from trustworthy_mcp.policy.classifier import (
    InjectionClassifier,
    HeuristicClassifier,
    ClassificationResult,
    AttackType,
)

logger = logging.getLogger(__name__)


@dataclass
class SanitizationResult:
    """Result of sanitization process."""
    original: str
    sanitized: str
    was_modified: bool
    warnings: list[str] = field(default_factory=list)
    classification: ClassificationResult | None = None


class Sanitizer:
    """Sanitizes input arguments to remove potential injection attacks.

    Implements iterative sanitization similar to SoftInstructionDefensePlugin.
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
        use_heuristics: bool = True,
        max_iterations: int = 3,
        risk_threshold: float = 0.7,
    ) -> None:
        """Initialize the sanitizer.

        Args:
            classifier: LLM-based classifier for deep analysis
            use_heuristics: Whether to use fast heuristic checks first
            max_iterations: Maximum sanitization iterations
            risk_threshold: Risk score threshold for blocking
        """
        self.classifier = classifier
        self.heuristic_classifier = HeuristicClassifier() if use_heuristics else None
        self.max_iterations = max_iterations
        self.risk_threshold = risk_threshold

    def sanitize_text(self, text: str, context: str | None = None) -> SanitizationResult:
        """Sanitize a single text string.

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

        # Fast heuristic check first
        if self.heuristic_classifier:
            heuristic_result = self.heuristic_classifier.classify(text)
            if heuristic_result and heuristic_result.risk_score >= self.risk_threshold:
                classification = heuristic_result
                warnings.append(f"Heuristic detection: {heuristic_result.explanation}")

        # Apply pattern-based sanitization
        for pattern, replacement in self.INJECTION_PATTERNS:
            new_text, count = re.subn(pattern, replacement, sanitized, flags=re.IGNORECASE)
            if count > 0:
                warnings.append(f"Removed pattern matching: {pattern}")
                sanitized = new_text

        # Deep LLM classification if available and text is still suspicious
        if self.classifier and (not classification or classification.risk_score < self.risk_threshold):
            classification = self.classifier.classify(sanitized, context)
            if classification.is_suspicious:
                warnings.append(f"LLM detection: {classification.explanation}")

        was_modified = sanitized != text

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            was_modified=was_modified,
            warnings=warnings,
            classification=classification,
        )

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
            if result.classification:
                if result.classification.risk_score >= self.risk_threshold:
                    return True
                if result.classification.recommended_action == "block":
                    return True
        return False


class OutputSanitizer:
    """Sanitizes tool outputs to prevent indirect injection via results."""

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

    def sanitize_output(self, output: str) -> tuple[str, bool]:
        """Sanitize tool output to remove instruction-like content.

        Args:
            output: Raw tool output

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

        return sanitized, was_modified

    def tag_as_untrusted(self, output: str, source: str) -> str:
        """Tag output as coming from an untrusted source.

        Args:
            output: The output content
            source: Description of the source (e.g., "web fetch", "file read")

        Returns:
            Tagged output
        """
        return f"[UNTRUSTED CONTENT FROM: {source}]\n{output}\n[END UNTRUSTED CONTENT]"
