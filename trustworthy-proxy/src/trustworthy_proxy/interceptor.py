"""
Request/response interceptor for the trustworthy proxy.

This module implements the core interception logic that applies
trustworthy-core security features to Claude Code API traffic.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Import from trustworthy-core
from trustworthy_core.patterns import is_suspicious, get_matched_patterns, calculate_risk_score
from trustworthy_core.deescalation import get_de_escalation_phrase, wrap_untrusted_content
from trustworthy_core.rubric import estimate_rubric_from_tools
from trustworthy_core.statistics import DetectionStatistics
from trustworthy_core.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class InterceptResult:
    """Result of intercepting a request or response."""

    modified: bool = False
    blocked: bool = False
    content: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    sanitized_count: int = 0


class RequestInterceptor:
    """Intercepts and sanitizes API requests before forwarding.

    This applies the full SoftInstructionDefense pattern to user messages
    before they reach Claude, providing prompt-level protection.
    """

    def __init__(
        self,
        enable_sanitization: bool = True,
        risk_threshold: float = 0.7,
        block_high_risk: bool = False,
    ) -> None:
        """Initialize the request interceptor.

        Args:
            enable_sanitization: Whether to sanitize suspicious content
            risk_threshold: Risk score threshold for warnings/blocking
            block_high_risk: Whether to block requests with high risk scores
        """
        self.enable_sanitization = enable_sanitization
        self.risk_threshold = risk_threshold
        self.block_high_risk = block_high_risk
        self.stats = DetectionStatistics()

        # Load config overrides
        config = get_config()
        if config.detection_threshold:
            self.risk_threshold = config.detection_threshold

    def intercept(self, request_body: Dict[str, Any]) -> InterceptResult:
        """Intercept and potentially modify an API request.

        Args:
            request_body: The JSON body of the API request

        Returns:
            InterceptResult with modifications or block decision
        """
        result = InterceptResult()
        messages = request_body.get("messages", [])

        if not messages:
            return result

        self.stats.record_message()

        modified_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                modified_msg, msg_result = self._process_user_message(msg)
                modified_messages.append(modified_msg)

                if msg_result.modified:
                    result.modified = True
                    result.sanitized_count += 1
                if msg_result.blocked:
                    result.blocked = True
                result.warnings.extend(msg_result.warnings)
                result.risk_score = max(result.risk_score, msg_result.risk_score)
            else:
                modified_messages.append(msg)

        if result.modified:
            request_body["messages"] = modified_messages
            result.content = json.dumps(request_body)
            self.stats.record_sanitization()

        if result.blocked:
            self.stats.record_halt()

        if result.risk_score >= self.risk_threshold:
            self.stats.record_detection()

        return result

    def _process_user_message(
        self,
        message: Dict[str, Any],
    ) -> tuple[Dict[str, Any], InterceptResult]:
        """Process a user message for potential injection.

        Args:
            message: The user message dict

        Returns:
            Tuple of (modified message, InterceptResult)
        """
        result = InterceptResult()
        content = message.get("content", "")

        # Handle both string and list content formats
        if isinstance(content, str):
            sanitized, msg_result = self._sanitize_text(content)
            if msg_result.modified:
                message = {**message, "content": sanitized}
                result.modified = True
            result.risk_score = msg_result.risk_score
            result.warnings = msg_result.warnings
            result.blocked = msg_result.blocked

        elif isinstance(content, list):
            # Handle multi-part content (text + images)
            modified_parts = []
            for part in content:
                if part.get("type") == "text":
                    text = part.get("text", "")
                    sanitized, part_result = self._sanitize_text(text)
                    if part_result.modified:
                        modified_parts.append({**part, "text": sanitized})
                        result.modified = True
                    else:
                        modified_parts.append(part)
                    result.risk_score = max(result.risk_score, part_result.risk_score)
                    result.warnings.extend(part_result.warnings)
                    if part_result.blocked:
                        result.blocked = True
                else:
                    modified_parts.append(part)

            if result.modified:
                message = {**message, "content": modified_parts}

        return message, result

    def _sanitize_text(self, text: str) -> tuple[str, InterceptResult]:
        """Sanitize a text string.

        Args:
            text: The text to sanitize

        Returns:
            Tuple of (sanitized text, InterceptResult)
        """
        result = InterceptResult()

        if not text.strip():
            return text, result

        # Check for suspicious patterns
        if is_suspicious(text):
            matches = get_matched_patterns(text)
            risk_score = calculate_risk_score(text)

            result.risk_score = risk_score
            result.warnings.append(f"Detected {len(matches)} suspicious pattern(s)")

            # Block if above threshold and blocking enabled
            if risk_score >= self.risk_threshold and self.block_high_risk:
                result.blocked = True
                result.warnings.append(f"Request blocked: risk score {risk_score:.2f}")
                return text, result

            # Sanitize if enabled
            if self.enable_sanitization:
                # Apply de-escalation phrase
                severity = "low"
                if risk_score >= 0.9:
                    severity = "critical"
                elif risk_score >= 0.7:
                    severity = "high"
                elif risk_score >= 0.5:
                    severity = "medium"

                phrase = get_de_escalation_phrase(severity)
                sanitized = f"{phrase}\n\n{text}"
                result.modified = True
                result.warnings.append(f"Applied {severity} de-escalation phrase")

                return sanitized, result

        return text, result

    def get_stats(self) -> Dict[str, Any]:
        """Get current detection statistics."""
        return self.stats.to_dict()


class ResponseInterceptor:
    """Intercepts API responses for analysis and optional filtering.

    Currently focuses on analysis/logging rather than modification,
    as modifying streaming responses is complex.
    """

    def __init__(
        self,
        enable_filtering: bool = False,
        log_tool_calls: bool = True,
    ) -> None:
        """Initialize the response interceptor.

        Args:
            enable_filtering: Whether to filter response content
            log_tool_calls: Whether to log tool call patterns
        """
        self.enable_filtering = enable_filtering
        self.log_tool_calls = log_tool_calls
        self.tool_call_history: List[Dict[str, Any]] = []

    def intercept(self, response_body: Dict[str, Any]) -> InterceptResult:
        """Intercept and analyze an API response.

        Args:
            response_body: The JSON body of the API response

        Returns:
            InterceptResult (usually unmodified)
        """
        result = InterceptResult()

        # Extract tool use for profiling
        if self.log_tool_calls:
            self._extract_tool_calls(response_body)

        # Response filtering is disabled by default
        # (Modifying Claude's responses could break tool use flows)
        if self.enable_filtering:
            # Future: could add response filtering here
            pass

        return result

    def _extract_tool_calls(self, response: Dict[str, Any]) -> None:
        """Extract tool calls from response for profiling.

        Args:
            response: The API response body
        """
        content = response.get("content", [])

        for block in content:
            if block.get("type") == "tool_use":
                tool_call = {
                    "name": block.get("name"),
                    "id": block.get("id"),
                    "input_keys": list(block.get("input", {}).keys()),
                }
                self.tool_call_history.append(tool_call)
                logger.debug(f"Tool call recorded: {tool_call['name']}")

    def get_tool_profile(self) -> Dict[str, Any]:
        """Get profiling data based on tool call history.

        Returns:
            Dict with tool usage patterns and estimated rubric
        """
        tool_names = [tc["name"] for tc in self.tool_call_history]

        if not tool_names:
            return {"tools_used": [], "rubric_estimate": None}

        # Estimate rubric from tool patterns
        rubric_estimate = estimate_rubric_from_tools(
            tools=tool_names,
            has_human_approval=True,  # Assume HITL in proxy mode
        )

        return {
            "tools_used": list(set(tool_names)),
            "tool_call_count": len(tool_names),
            "rubric_estimate": rubric_estimate,
        }

    def clear_history(self) -> None:
        """Clear tool call history."""
        self.tool_call_history = []
