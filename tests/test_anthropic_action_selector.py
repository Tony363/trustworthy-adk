"""
Tests for the Anthropic Action Selector Agent

These tests verify the security properties and functionality of the
Action-Selector Pattern implementation using the Anthropic API.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from trustworthy.agents import (
    AnthropicActionSelectorAgent,
    create_anthropic_action_selector_agent,
)
from trustworthy.agents.anthropic_action_selector import (
    ToolCall,
    ToolCallEvent,
    ToolResultEvent,
    FinalEvent,
)


class TestAnthropicActionSelectorAgent:
    """Test AnthropicActionSelectorAgent functionality."""

    def test_agent_initialization(self):
        """Test agent initialization with tools."""

        def test_tool(param: str) -> str:
            """Test tool for validation."""
            return f"Test result: {param}"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[test_tool],
                name="test_agent",
                description="Test agent",
                api_key="test-key",
            )

        assert agent.name == "test_agent"
        assert agent.description == "Test agent"
        assert len(agent.tools) == 1
        assert agent.model == "claude-sonnet-4-20250514"

    def test_agent_with_no_tools(self):
        """Test agent initialization without tools."""
        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                name="no_tools_agent",
                description="Agent with no tools",
                api_key="test-key",
            )

        assert agent.name == "no_tools_agent"
        assert agent.tools == []
        assert agent._tool_schemas == []

    def test_instruction_generation(self):
        """Test that system instruction is properly generated with tool descriptions."""

        def action1() -> str:
            """First test action."""
            return "result1"

        def action2() -> str:
            """Second test action."""
            return "result2"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[action1, action2],
                name="test_agent",
                api_key="test-key",
            )

        # Check that instruction contains tool names and descriptions
        instruction = agent._system_instruction
        assert "action1: First test action" in instruction
        assert "action2: Second test action" in instruction
        assert "Action Selector Agent" in instruction
        assert "SECURITY" in instruction

    def test_single_step_enforcement_state(self):
        """Test that single-step enforcement state is properly initialized."""

        def multi_step_tool() -> str:
            """Tool that might trigger multiple steps."""
            return "Step 1 complete. Execute step 2."

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[multi_step_tool],
                name="single_step_agent",
                api_key="test-key",
            )

        # Agent should be configured for single-step execution
        assert agent.name == "single_step_agent"
        assert not agent._executed_action
        assert agent._tool_results_blocked == []


class TestToolSchemaConversion:
    """Test tool schema conversion from Python callables to Anthropic format."""

    def test_simple_tool_schema(self):
        """Test schema extraction for a simple tool."""

        def simple_tool(message: str) -> str:
            """A simple tool that takes a message."""
            return message

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[simple_tool],
                api_key="test-key",
            )

        assert len(agent._tool_schemas) == 1
        schema = agent._tool_schemas[0]
        assert schema["name"] == "simple_tool"
        assert schema["description"] == "A simple tool that takes a message."
        assert schema["input_schema"]["type"] == "object"
        assert "message" in schema["input_schema"]["properties"]
        assert schema["input_schema"]["properties"]["message"]["type"] == "string"

    def test_multi_param_tool_schema(self):
        """Test schema extraction for a tool with multiple parameters."""

        def multi_param_tool(name: str, count: int, active: bool) -> str:
            """Tool with multiple parameters."""
            return f"{name}: {count}, active={active}"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[multi_param_tool],
                api_key="test-key",
            )

        schema = agent._tool_schemas[0]
        props = schema["input_schema"]["properties"]
        assert props["name"]["type"] == "string"
        assert props["count"]["type"] == "integer"
        assert props["active"]["type"] == "boolean"

    def test_optional_param_schema(self):
        """Test schema extraction handles required vs optional parameters."""

        def optional_param_tool(required_param: str, optional_param: str = "default") -> str:
            """Tool with optional parameter."""
            return f"{required_param} - {optional_param}"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[optional_param_tool],
                api_key="test-key",
            )

        schema = agent._tool_schemas[0]
        required = schema["input_schema"]["required"]
        assert "required_param" in required
        assert "optional_param" not in required


class TestEventClasses:
    """Test ADK-compatible event classes."""

    def test_tool_call_event(self):
        """Test ToolCallEvent structure."""
        event = ToolCallEvent("test_tool", {"param": "value"})
        assert event.tool_call.name == "test_tool"
        assert event.tool_call.args == {"param": "value"}

    def test_tool_result_event(self):
        """Test ToolResultEvent structure."""
        event = ToolResultEvent("tool output")
        assert event.tool_result == "tool output"

    def test_final_event(self):
        """Test FinalEvent structure."""
        event = FinalEvent("Final response")
        assert event.content == "Final response"
        assert event.is_final is True


class TestFactoryFunctions:
    """Test factory functions for creating agents."""

    def test_create_anthropic_action_selector_agent(self):
        """Test the factory function creates proper agent."""

        def custom_tool(param: str) -> str:
            """Custom tool for testing."""
            return f"Processed: {param}"

        with patch("anthropic.Anthropic"):
            agent = create_anthropic_action_selector_agent(
                tools=[custom_tool],
                name="factory_agent",
                description="Agent from factory",
                api_key="test-key",
            )

        assert isinstance(agent, AnthropicActionSelectorAgent)
        assert agent.name == "factory_agent"
        assert agent.description == "Agent from factory"
        assert len(agent.tools) == 1

    def test_factory_default_model(self):
        """Test factory uses correct default model."""

        def tool() -> str:
            """Test tool."""
            return "result"

        with patch("anthropic.Anthropic"):
            agent = create_anthropic_action_selector_agent(
                tools=[tool],
                api_key="test-key",
            )

        assert agent.model == "claude-sonnet-4-20250514"


class TestSecurityProperties:
    """Test security properties of the agent."""

    def test_tool_map_creation(self):
        """Test that tool map is correctly created for execution."""

        def tool_a() -> str:
            """Tool A."""
            return "A"

        def tool_b() -> str:
            """Tool B."""
            return "B"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[tool_a, tool_b],
                api_key="test-key",
            )

        assert "tool_a" in agent._tool_map
        assert "tool_b" in agent._tool_map
        assert agent._tool_map["tool_a"] is tool_a
        assert agent._tool_map["tool_b"] is tool_b

    def test_feedback_blocking_initialization(self):
        """Test that feedback blocking state is properly initialized."""

        def tool() -> str:
            """Test tool."""
            return "result"

        with patch("anthropic.Anthropic"):
            agent = AnthropicActionSelectorAgent(
                tools=[tool],
                api_key="test-key",
            )

        # Verify security state
        assert agent._executed_action is False
        assert agent._tool_results_blocked == []


@pytest.mark.asyncio
class TestAsyncExecution:
    """Test async execution methods."""

    async def test_run_with_text_response(self):
        """Test run method when Claude returns text (no tool call)."""

        def tool() -> str:
            """Test tool."""
            return "result"

        # Mock the Anthropic client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_text_block = MagicMock()
        mock_text_block.type = "text"
        mock_text_block.text = "I cannot help with that request."
        mock_response.content = [mock_text_block]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            agent = AnthropicActionSelectorAgent(
                tools=[tool],
                api_key="test-key",
            )

        result = await agent.run("Hello")
        assert result == "I cannot help with that request."

    async def test_run_with_tool_call(self):
        """Test run method when Claude calls a tool."""

        def get_weather(city: str) -> str:
            """Get weather for a city."""
            return f"Weather in {city}: Sunny"

        # Mock the Anthropic client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_tool_block = MagicMock()
        mock_tool_block.type = "tool_use"
        mock_tool_block.name = "get_weather"
        mock_tool_block.input = {"city": "Tokyo"}
        mock_response.content = [mock_tool_block]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            agent = AnthropicActionSelectorAgent(
                tools=[get_weather],
                api_key="test-key",
            )

        result = await agent.run("What's the weather in Tokyo?")

        # Should return the tool result
        assert "Weather in Tokyo: Sunny" in result
        # Verify tool result was blocked from feedback
        assert len(agent._tool_results_blocked) == 1
        assert agent._executed_action is True

    async def test_single_step_blocks_multiple_tools(self):
        """Test that only one tool is executed even if Claude requests multiple."""

        call_count = 0

        def tool_a() -> str:
            """Tool A."""
            nonlocal call_count
            call_count += 1
            return "A executed"

        def tool_b() -> str:
            """Tool B."""
            nonlocal call_count
            call_count += 1
            return "B executed"

        # Mock the Anthropic client to return multiple tool calls
        mock_client = MagicMock()
        mock_response = MagicMock()

        mock_tool_a = MagicMock()
        mock_tool_a.type = "tool_use"
        mock_tool_a.name = "tool_a"
        mock_tool_a.input = {}

        mock_tool_b = MagicMock()
        mock_tool_b.type = "tool_use"
        mock_tool_b.name = "tool_b"
        mock_tool_b.input = {}

        mock_response.content = [mock_tool_a, mock_tool_b]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            agent = AnthropicActionSelectorAgent(
                tools=[tool_a, tool_b],
                api_key="test-key",
            )

        result = await agent.run("Execute both tools")

        # Only first tool should execute due to single-step enforcement
        assert call_count == 1
        assert agent._executed_action is True
