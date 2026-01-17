"""Tests for rubric.py - 4D Agent Profiling Rubric."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from trustworthy_core.rubric import (
    AutonomyLevel,
    EfficacyLevel,
    GoalComplexityLevel,
    GeneralityLevel,
    JUDGE_SYSTEM_INSTRUCTION,
    PYDANTIC_AVAILABLE,
    estimate_rubric_from_tools,
)


class TestAutonomyLevel:
    """Tests for AutonomyLevel enum."""

    def test_all_levels_exist(self):
        """All 5 autonomy levels should exist."""
        assert AutonomyLevel.OPERATOR is not None
        assert AutonomyLevel.COLLABORATOR is not None
        assert AutonomyLevel.CONSULTANT is not None
        assert AutonomyLevel.APPROVER is not None
        assert AutonomyLevel.OBSERVER is not None

    def test_level_property(self):
        """Level property should return correct format."""
        assert AutonomyLevel.OPERATOR.level == "L1"
        assert AutonomyLevel.COLLABORATOR.level == "L2"
        assert AutonomyLevel.CONSULTANT.level == "L3"
        assert AutonomyLevel.APPROVER.level == "L4"
        assert AutonomyLevel.OBSERVER.level == "L5"

    def test_label_property(self):
        """Label property should return human-readable names."""
        assert AutonomyLevel.OPERATOR.label == "Operator"
        assert AutonomyLevel.COLLABORATOR.label == "Collaborator"
        assert AutonomyLevel.CONSULTANT.label == "Consultant"
        assert AutonomyLevel.APPROVER.label == "Approver"
        assert AutonomyLevel.OBSERVER.label == "Observer"

    def test_numeric_property(self):
        """Numeric property should return integer values."""
        assert AutonomyLevel.OPERATOR.numeric == 1
        assert AutonomyLevel.COLLABORATOR.numeric == 2
        assert AutonomyLevel.CONSULTANT.numeric == 3
        assert AutonomyLevel.APPROVER.numeric == 4
        assert AutonomyLevel.OBSERVER.numeric == 5

    def test_numeric_ordering(self):
        """Higher autonomy should have higher numeric value."""
        assert AutonomyLevel.OPERATOR.numeric < AutonomyLevel.OBSERVER.numeric


class TestEfficacyLevel:
    """Tests for EfficacyLevel enum."""

    def test_all_levels_exist(self):
        """All 6 efficacy levels should exist (E.0 to E.5)."""
        assert EfficacyLevel.OBSERVATION_ONLY is not None
        assert EfficacyLevel.CONSTRAINED_SIMULATED is not None
        assert EfficacyLevel.EPISTEMIC_MEDIATED is not None
        assert EfficacyLevel.INTERMEDIATE_MEDIATED is not None
        assert EfficacyLevel.COMPREHENSIVE_PHYSICAL is not None
        assert EfficacyLevel.UNBOUNDED_PHYSICAL is not None

    def test_level_property(self):
        """Level property should return correct format."""
        assert EfficacyLevel.OBSERVATION_ONLY.level == "E.0"
        assert EfficacyLevel.CONSTRAINED_SIMULATED.level == "E.1"
        assert EfficacyLevel.INTERMEDIATE_MEDIATED.level == "E.3"
        assert EfficacyLevel.UNBOUNDED_PHYSICAL.level == "E.5"

    def test_numeric_property(self):
        """Numeric property should return correct values."""
        assert EfficacyLevel.OBSERVATION_ONLY.numeric == 0
        assert EfficacyLevel.UNBOUNDED_PHYSICAL.numeric == 5

    def test_label_property(self):
        """Label property should return descriptive names."""
        assert "Observation" in EfficacyLevel.OBSERVATION_ONLY.label
        assert "Unbounded" in EfficacyLevel.UNBOUNDED_PHYSICAL.label


class TestGoalComplexityLevel:
    """Tests for GoalComplexityLevel enum."""

    def test_all_levels_exist(self):
        """All 6 goal complexity levels should exist (GC.0 to GC.5)."""
        assert GoalComplexityLevel.NO_GOAL is not None
        assert GoalComplexityLevel.ATOMIC is not None
        assert GoalComplexityLevel.SEQUENTIAL is not None
        assert GoalComplexityLevel.ADAPTIVE is not None
        assert GoalComplexityLevel.STRATEGIC is not None
        assert GoalComplexityLevel.AUTOPOIETIC is not None

    def test_level_property(self):
        """Level property should return correct format."""
        assert GoalComplexityLevel.NO_GOAL.level == "GC.0"
        assert GoalComplexityLevel.ATOMIC.level == "GC.1"
        assert GoalComplexityLevel.SEQUENTIAL.level == "GC.2"
        assert GoalComplexityLevel.AUTOPOIETIC.level == "GC.5"

    def test_numeric_property(self):
        """Numeric property should return correct values."""
        assert GoalComplexityLevel.NO_GOAL.numeric == 0
        assert GoalComplexityLevel.AUTOPOIETIC.numeric == 5

    def test_label_property(self):
        """Label property should return descriptive names."""
        assert GoalComplexityLevel.NO_GOAL.label == "No Goal"
        assert GoalComplexityLevel.ATOMIC.label == "Atomic"
        assert GoalComplexityLevel.STRATEGIC.label == "Strategic"


class TestGeneralityLevel:
    """Tests for GeneralityLevel enum."""

    def test_all_levels_exist(self):
        """All 5 generality levels should exist (G.1 to G.5)."""
        assert GeneralityLevel.NARROW is not None
        assert GeneralityLevel.DOMAIN_SPECIFIC is not None
        assert GeneralityLevel.CROSS_DOMAIN is not None
        assert GeneralityLevel.GENERAL is not None
        assert GeneralityLevel.SUPER_GENERAL is not None

    def test_level_property(self):
        """Level property should return correct format."""
        assert GeneralityLevel.NARROW.level == "G.1"
        assert GeneralityLevel.DOMAIN_SPECIFIC.level == "G.2"
        assert GeneralityLevel.SUPER_GENERAL.level == "G.5"

    def test_numeric_property(self):
        """Numeric property should return correct values (1-5, not 0-5)."""
        assert GeneralityLevel.NARROW.numeric == 1
        assert GeneralityLevel.SUPER_GENERAL.numeric == 5

    def test_label_property(self):
        """Label property should return descriptive names."""
        assert GeneralityLevel.NARROW.label == "Narrow"
        assert GeneralityLevel.DOMAIN_SPECIFIC.label == "Domain Specific"


class TestEstimateRubricFromTools:
    """Tests for estimate_rubric_from_tools() function."""

    def test_returns_dict(self):
        """Should return a dictionary."""
        result = estimate_rubric_from_tools(["read_file"])
        assert isinstance(result, dict)

    def test_contains_all_dimensions(self):
        """Result should contain all 4 dimensions."""
        result = estimate_rubric_from_tools(["read_file"])
        assert "autonomy" in result
        assert "efficacy" in result
        assert "goal_complexity" in result
        assert "generality" in result

    def test_each_dimension_has_level_and_label(self):
        """Each dimension should have level and label."""
        result = estimate_rubric_from_tools(["read_file"])
        for dim in ["autonomy", "efficacy", "goal_complexity", "generality"]:
            assert "level" in result[dim]
            assert "label" in result[dim]

    def test_read_only_tools_low_efficacy(self):
        """Read-only tools should estimate low efficacy."""
        result = estimate_rubric_from_tools(["read_file", "list_directory"])
        # E.0-E.2 are low efficacy
        efficacy_level = result["efficacy"]["level"]
        assert efficacy_level in ["E.0", "E.1", "E.2"]

    def test_execute_command_high_efficacy(self):
        """Execute command should estimate high efficacy."""
        result = estimate_rubric_from_tools(["execute_command"])
        efficacy_level = result["efficacy"]["level"]
        # E.3+ is higher efficacy
        assert efficacy_level in ["E.3", "E.4", "E.5"]

    def test_write_tools_medium_efficacy(self):
        """Write tools should estimate medium efficacy."""
        result = estimate_rubric_from_tools(["write_file", "create_directory"])
        efficacy_level = result["efficacy"]["level"]
        assert efficacy_level in ["E.2", "E.3"]

    def test_human_approval_affects_autonomy(self):
        """Human approval should affect autonomy level."""
        without_approval = estimate_rubric_from_tools(
            ["execute_command"], has_human_approval=False
        )
        with_approval = estimate_rubric_from_tools(
            ["execute_command"], has_human_approval=True
        )
        # With approval = APPROVER pattern (L4), can do more with human approval
        # Without approval = CONSULTANT pattern (L3), can only advise
        # Higher L number = more autonomy delegated to the agent
        without_level = int(without_approval["autonomy"]["level"][1])
        with_level = int(with_approval["autonomy"]["level"][1])
        assert with_level >= without_level  # APPROVER >= CONSULTANT

    def test_empty_tools_list(self):
        """Should handle empty tools list."""
        result = estimate_rubric_from_tools([])
        assert isinstance(result, dict)
        # Should return minimal capabilities
        assert result["efficacy"]["level"] == "E.0"

    def test_http_tools_affect_generality(self):
        """HTTP/network tools should increase generality."""
        local_result = estimate_rubric_from_tools(["read_file"])
        network_result = estimate_rubric_from_tools(["http_request", "fetch_url"])

        local_gen = int(local_result["generality"]["level"][2])
        network_gen = int(network_result["generality"]["level"][2])
        assert network_gen >= local_gen

    def test_max_iterations_affects_goal_complexity(self):
        """Max iterations parameter should affect goal complexity."""
        single_step = estimate_rubric_from_tools(
            ["read_file"], max_iterations=1
        )
        multi_step = estimate_rubric_from_tools(
            ["read_file"], max_iterations=None
        )

        single_gc = int(single_step["goal_complexity"]["level"][3])
        multi_gc = int(multi_step["goal_complexity"]["level"][3])
        assert multi_gc >= single_gc


class TestJudgeSystemInstruction:
    """Tests for JUDGE_SYSTEM_INSTRUCTION constant."""

    def test_instruction_not_empty(self):
        """Judge instruction should not be empty."""
        assert JUDGE_SYSTEM_INSTRUCTION
        assert len(JUDGE_SYSTEM_INSTRUCTION) > 100

    def test_contains_evaluation_guidance(self):
        """Should contain evaluation guidance."""
        assert "Autonomy" in JUDGE_SYSTEM_INSTRUCTION
        assert "Efficacy" in JUDGE_SYSTEM_INSTRUCTION
        assert "Goal" in JUDGE_SYSTEM_INSTRUCTION
        assert "Generality" in JUDGE_SYSTEM_INSTRUCTION

    def test_contains_json_format(self):
        """Should contain JSON output format guidance."""
        assert "json" in JUDGE_SYSTEM_INSTRUCTION.lower()


class TestPydanticAvailability:
    """Tests for PYDANTIC_AVAILABLE flag."""

    def test_flag_is_boolean(self):
        """PYDANTIC_AVAILABLE should be a boolean."""
        assert isinstance(PYDANTIC_AVAILABLE, bool)

    def test_enums_work_without_pydantic(self):
        """Enums should work regardless of pydantic availability."""
        # These should always work
        assert AutonomyLevel.OPERATOR.level == "L1"
        assert EfficacyLevel.OBSERVATION_ONLY.numeric == 0
        assert GoalComplexityLevel.ATOMIC.label == "Atomic"
        assert GeneralityLevel.NARROW.level == "G.1"

    def test_estimate_works_without_pydantic(self):
        """estimate_rubric_from_tools should work without pydantic."""
        result = estimate_rubric_from_tools(["read_file"])
        assert isinstance(result, dict)
