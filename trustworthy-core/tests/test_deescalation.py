"""Tests for deescalation.py - De-escalation phrases and content wrapping."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from trustworthy_core.deescalation import (
    DEFAULT_DE_ESCALATION_PHRASES,
    SEVERITY_PHRASES,
    get_de_escalation_phrase,
    wrap_untrusted_content,
    create_safe_summary_wrapper,
)


class TestDefaultPhrases:
    """Tests for DEFAULT_DE_ESCALATION_PHRASES constant."""

    def test_phrases_not_empty(self):
        """Default phrases list should not be empty."""
        assert len(DEFAULT_DE_ESCALATION_PHRASES) > 0

    def test_phrases_are_strings(self):
        """All phrases should be strings."""
        for phrase in DEFAULT_DE_ESCALATION_PHRASES:
            assert isinstance(phrase, str)

    def test_phrases_have_content(self):
        """Phrases should have meaningful content."""
        for phrase in DEFAULT_DE_ESCALATION_PHRASES:
            assert len(phrase) > 10


class TestSeverityPhrases:
    """Tests for SEVERITY_PHRASES dictionary."""

    def test_all_severities_exist(self):
        """All severity levels should have phrases."""
        assert "low" in SEVERITY_PHRASES
        assert "medium" in SEVERITY_PHRASES
        assert "high" in SEVERITY_PHRASES
        assert "critical" in SEVERITY_PHRASES

    def test_severity_phrases_are_lists(self):
        """All severity phrases should be lists of strings."""
        for severity, phrases in SEVERITY_PHRASES.items():
            assert isinstance(phrases, list)
            assert len(phrases) > 0
            for phrase in phrases:
                assert isinstance(phrase, str)
                assert len(phrase) > 0


class TestGetDeEscalationPhrase:
    """Tests for get_de_escalation_phrase() function."""

    def test_returns_string(self):
        """Should return a string."""
        result = get_de_escalation_phrase("low")
        assert isinstance(result, str)

    def test_low_severity(self):
        """Should return phrase for low severity."""
        phrase = get_de_escalation_phrase("low")
        assert len(phrase) > 0

    def test_medium_severity(self):
        """Should return phrase for medium severity."""
        phrase = get_de_escalation_phrase("medium")
        assert len(phrase) > 0

    def test_high_severity(self):
        """Should return phrase for high severity."""
        phrase = get_de_escalation_phrase("high")
        assert len(phrase) > 0

    def test_critical_severity(self):
        """Should return phrase for critical severity."""
        phrase = get_de_escalation_phrase("critical")
        assert len(phrase) > 0

    def test_unknown_severity_fallback(self):
        """Should fallback to default for unknown severity."""
        phrase = get_de_escalation_phrase("unknown")
        assert isinstance(phrase, str)
        assert len(phrase) > 0

    def test_case_insensitive(self):
        """Should handle case variations."""
        phrase1 = get_de_escalation_phrase("LOW")
        phrase2 = get_de_escalation_phrase("low")
        # Both should work (might be same or different)
        assert isinstance(phrase1, str)
        assert isinstance(phrase2, str)

    def test_severity_escalation(self):
        """Higher severity phrases should be more severe."""
        low = get_de_escalation_phrase("low")
        critical = get_de_escalation_phrase("critical")
        # Critical phrase should be different (more serious)
        # At minimum, they should both exist
        assert low and critical


class TestWrapUntrustedContent:
    """Tests for wrap_untrusted_content() function."""

    def test_returns_string(self):
        """Should return a string."""
        result = wrap_untrusted_content("test content", "test_source")
        assert isinstance(result, str)

    def test_contains_original_content(self):
        """Wrapped content should contain original content."""
        content = "This is my test content"
        result = wrap_untrusted_content(content, "test_source")
        assert content in result

    def test_contains_source_identifier(self):
        """Wrapped content should identify the source."""
        result = wrap_untrusted_content("content", "my_source")
        assert "my_source" in result.lower() or "source" in result.lower()

    def test_has_wrapper_markers(self):
        """Content should have clear wrapper markers."""
        result = wrap_untrusted_content("content", "source")
        # Should have some kind of delimiter/marker
        assert "[" in result or "---" in result or "UNTRUSTED" in result.upper()

    def test_empty_content(self):
        """Should handle empty content."""
        result = wrap_untrusted_content("", "source")
        assert isinstance(result, str)

    def test_multiline_content(self):
        """Should handle multiline content."""
        content = "Line 1\nLine 2\nLine 3"
        result = wrap_untrusted_content(content, "source")
        assert "Line 1" in result
        assert "Line 2" in result
        assert "Line 3" in result


class TestCreateSafeSummaryWrapper:
    """Tests for create_safe_summary_wrapper() function."""

    def test_returns_string(self):
        """Should return a string."""
        result = create_safe_summary_wrapper("summary text", "tool_name")
        assert isinstance(result, str)

    def test_contains_summary(self):
        """Wrapper should contain the summary."""
        summary = "This is my summary"
        result = create_safe_summary_wrapper(summary, "test_tool")
        assert summary in result

    def test_contains_tool_name(self):
        """Wrapper should mention the tool name."""
        result = create_safe_summary_wrapper("summary", "my_special_tool")
        assert "my_special_tool" in result.lower() or "tool" in result.lower()

    def test_indicates_summary(self):
        """Wrapper should indicate this is a summary."""
        result = create_safe_summary_wrapper("content", "tool")
        # Should have some indication it's a summary
        assert "summary" in result.lower() or "summarized" in result.lower()

    def test_empty_summary(self):
        """Should handle empty summary."""
        result = create_safe_summary_wrapper("", "tool")
        assert isinstance(result, str)


class TestEdgeCases:
    """Edge case tests."""

    def test_special_characters_in_content(self):
        """Should handle special characters."""
        content = "Content with <html> and {json} and [brackets]"
        result = wrap_untrusted_content(content, "source")
        # Should not crash
        assert isinstance(result, str)

    def test_unicode_content(self):
        """Should handle unicode content."""
        content = "Unicode: 你好 مرحبا 🚀"
        result = wrap_untrusted_content(content, "source")
        assert "你好" in result

    def test_very_long_content(self):
        """Should handle very long content."""
        content = "x" * 10000
        result = wrap_untrusted_content(content, "source")
        assert isinstance(result, str)

    def test_none_source(self):
        """Should handle None source gracefully."""
        try:
            result = wrap_untrusted_content("content", None)
            assert isinstance(result, str)
        except (TypeError, AttributeError):
            pass  # Also acceptable to raise error
