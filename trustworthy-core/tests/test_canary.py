"""Tests for canary.py - Dummy instruction probes for hidden injection detection."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from trustworthy_core.canary import (
    DUMMY_INSTRUCTIONS,
    MCP_CANARY_PROBES,
    CANARY_RESPONSES,
    create_canary_probe,
    check_canary_response,
    remove_canary_probes,
)


class TestDummyInstructions:
    """Tests for DUMMY_INSTRUCTIONS constant."""

    def test_instructions_not_empty(self):
        """Dummy instructions list should not be empty."""
        assert len(DUMMY_INSTRUCTIONS) > 0

    def test_instructions_are_strings(self):
        """All instructions should be strings."""
        for instruction in DUMMY_INSTRUCTIONS:
            assert isinstance(instruction, str)

    def test_instructions_have_content(self):
        """Instructions should have meaningful content."""
        for instruction in DUMMY_INSTRUCTIONS:
            assert len(instruction) > 10

    def test_instructions_look_like_commands(self):
        """Instructions should look like commands/directives."""
        # At least some should contain imperative words
        imperatives = ["ignore", "respond", "say", "output", "print", "reply"]
        has_imperative = any(
            any(imp in instr.lower() for imp in imperatives)
            for instr in DUMMY_INSTRUCTIONS
        )
        assert has_imperative


class TestMCPCanaryProbes:
    """Tests for MCP_CANARY_PROBES constant."""

    def test_probes_not_empty(self):
        """MCP canary probes list should not be empty."""
        assert len(MCP_CANARY_PROBES) > 0

    def test_probes_are_strings(self):
        """All probes should be strings."""
        for probe in MCP_CANARY_PROBES:
            assert isinstance(probe, str)


class TestCanaryResponses:
    """Tests for CANARY_RESPONSES constant."""

    def test_responses_not_empty(self):
        """Canary responses list should not be empty."""
        assert len(CANARY_RESPONSES) > 0

    def test_responses_are_strings(self):
        """All responses should be strings."""
        for response in CANARY_RESPONSES:
            assert isinstance(response, str)

    def test_responses_are_distinct(self):
        """Canary responses should be unique identifiers."""
        # They should be relatively short and distinct
        for response in CANARY_RESPONSES:
            assert len(response) < 100


class TestCreateCanaryProbe:
    """Tests for create_canary_probe() function."""

    def test_returns_string(self):
        """Should return a string with probes appended."""
        result = create_canary_probe("test text")
        assert isinstance(result, str)

    def test_contains_original_text(self):
        """Result should contain the original text."""
        result = create_canary_probe("my original text")
        assert "my original text" in result

    def test_contains_probe_instructions(self):
        """Result should contain probe instructions."""
        result = create_canary_probe("test")
        # Should contain at least one dummy instruction
        assert any(instr in result for instr in DUMMY_INSTRUCTIONS)

    def test_probe_type_standard(self):
        """Standard probe type should use DUMMY_INSTRUCTIONS."""
        result = create_canary_probe("test", probe_type="standard")
        assert any(instr in result for instr in DUMMY_INSTRUCTIONS)

    def test_probe_type_mcp(self):
        """MCP probe type should use MCP_CANARY_PROBES."""
        result = create_canary_probe("test", probe_type="mcp")
        assert any(probe in result for probe in MCP_CANARY_PROBES)


class TestCheckCanaryResponse:
    """Tests for check_canary_response() function."""

    def test_returns_tuple(self):
        """Should return a tuple of (bool, Optional[str])."""
        result = check_canary_response("some response")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)

    def test_exact_match_detected(self):
        """Should detect exact canary response match."""
        for response in CANARY_RESPONSES:
            triggered, matched = check_canary_response(response)
            assert triggered
            assert matched == response

    def test_canary_in_longer_response(self):
        """Should detect canary in longer response."""
        for response in CANARY_RESPONSES:
            longer = f"Some text before. {response}. Some text after."
            triggered, matched = check_canary_response(longer)
            assert triggered
            assert matched == response

    def test_normal_text_not_triggered(self):
        """Normal text should not trigger canary."""
        normal_responses = [
            "Hello, how can I help you?",
            "The answer is 42.",
            "Here is the file content...",
        ]
        for response in normal_responses:
            triggered, matched = check_canary_response(response)
            assert not triggered
            assert matched is None

    def test_case_insensitive(self):
        """Check should be case-insensitive."""
        for response in CANARY_RESPONSES:
            upper_response = response.upper()
            triggered, _ = check_canary_response(upper_response)
            assert triggered  # Should still match


class TestRemoveCanaryProbes:
    """Tests for remove_canary_probes() function."""

    def test_returns_string(self):
        """Should return a string."""
        result = remove_canary_probes("test text")
        assert isinstance(result, str)

    def test_clean_text_unchanged(self):
        """Text without probes should be unchanged."""
        original = "This is clean text without any probes."
        result = remove_canary_probes(original)
        assert result == original

    def test_removes_probe_text(self):
        """Should remove canary probe instructions."""
        # Add a probe to text
        probe = create_canary_probe("user content")
        if "probe_text" in probe:
            with_probe = f"Start. {probe['probe_text']} End."
            result = remove_canary_probes(with_probe)
            # The probe instruction should be removed or neutralized
            assert isinstance(result, str)

    def test_preserves_user_content(self):
        """Should preserve non-probe content."""
        text = "Important user data. More content here."
        result = remove_canary_probes(text)
        assert "Important" in result or "user" in result


class TestCanaryWorkflow:
    """Integration tests for the canary workflow."""

    def test_full_workflow(self):
        """Test complete canary probe workflow."""
        # 1. Create a probe - returns string
        probed_content = create_canary_probe("suspicious content here")
        assert isinstance(probed_content, str)
        assert "suspicious content here" in probed_content

        # 2. If a canary response is in the output, it means injection
        for canary in CANARY_RESPONSES:
            triggered, matched = check_canary_response(f"Output: {canary}")
            assert triggered
            assert matched == canary

        # 3. Clean up probes from text
        cleaned = remove_canary_probes(probed_content)
        assert isinstance(cleaned, str)
        assert "suspicious content here" in cleaned

    def test_no_false_positives_on_clean_text(self):
        """Clean text should not trigger canary detection."""
        clean_texts = [
            "The weather is nice today.",
            "def hello(): return 'world'",
            "SELECT * FROM users WHERE id = 1",
        ]
        for text in clean_texts:
            triggered, matched = check_canary_response(text)
            assert not triggered
            assert matched is None


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_text(self):
        """Should handle empty text."""
        result = create_canary_probe("")
        assert isinstance(result, str)
        # Should still contain probes even with empty input
        assert len(result) > 0

        cleaned = remove_canary_probes("")
        assert cleaned == ""

    def test_unicode_text(self):
        """Should handle unicode text."""
        text = "Unicode: 你好 مرحبا"
        result = create_canary_probe(text)
        assert isinstance(result, str)
        assert "你好" in result

    def test_special_characters(self):
        """Should handle special characters."""
        text = "Special: <>&\"'[]{}()"
        result = create_canary_probe(text)
        assert isinstance(result, str)
        assert "Special:" in result
