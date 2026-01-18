"""
Anthropic Action Selector Agent Implementation for ADK

This module implements the Action-Selector Pattern using Claude via the Anthropic API.
It provides the same security guarantees as the Gemini-based ActionSelectorAgent:

Key Security Features:
- No feedback from tool execution back to the agent
- Single-step execution with immediate return to user
- Predefined tools only (no dynamic tool creation)
- Immunity to Indirect Prompt Injection (IPI) attacks

Architectural Principle: Control Flow Isolation / Least Autonomy
"""

import asyncio
import inspect
import logging
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, get_type_hints

import anthropic

logger = logging.getLogger(__name__)


class ToolCall:
    """Represents a tool call for ADK compatibility."""

    def __init__(self, name: str, args: Dict[str, Any]):
        self.name = name
        self.args = args


class ToolCallEvent:
    """ADK-compatible tool call event."""

    def __init__(self, tool_name: str, args: Dict[str, Any]):
        self.tool_call = ToolCall(name=tool_name, args=args)


class ToolResultEvent:
    """ADK-compatible tool result event."""

    def __init__(self, result: Any):
        self.tool_result = result


class FinalEvent:
    """Final response event."""

    def __init__(self, content: str):
        self.content = content
        self.is_final = True


class AnthropicActionSelectorAgent:
    """
    Action Selector Agent using Claude via Anthropic API.

    This agent implements the Action-Selector Pattern with the same security
    guarantees as the Gemini-based ActionSelectorAgent:

    Security Properties:
    - Immune to Indirect Prompt Injection (IPI) through tool observations
    - Operates with minimal autonomy and well-defined action space
    - No iterative reasoning or multi-step workflows
    - Deterministic action selection from predefined tools
    - Tool results NEVER feed back to Claude context
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        name: str = "anthropic_action_selector",
        description: str = "Secure action selection agent using Claude",
        tools: Optional[List[Callable]] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 1024,
        **kwargs,
    ):
        """
        Initialize the Anthropic Action Selector Agent.

        Args:
            model: The Claude model to use (e.g., "claude-sonnet-4-20250514")
            name: Name of the agent
            description: Description of the agent's purpose
            tools: List of callable tools the agent can use
            api_key: Anthropic API key (or use ANTHROPIC_API_KEY env var)
            max_tokens: Maximum tokens for Claude response
            **kwargs: Additional arguments (reserved for future use)
        """
        self.model = model
        self.name = name
        self.description = description
        self.tools = tools or []
        self.max_tokens = max_tokens

        # Initialize Anthropic client (uses ANTHROPIC_API_KEY env var if api_key not provided)
        self.client = anthropic.Anthropic(api_key=api_key)

        # Build tool schemas for Claude
        self._tool_schemas = self._build_tool_schemas(self.tools)
        self._tool_map = {tool.__name__: tool for tool in self.tools}

        # Security tracking
        self._executed_action = False
        self._tool_results_blocked: List[Any] = []

        # Build system instruction
        self._system_instruction = self._build_system_instruction()

        logger.info(f"AnthropicActionSelectorAgent initialized: {name}")

    def _build_tool_schemas(self, tools: List[Callable]) -> List[Dict[str, Any]]:
        """
        Convert Python callables to Anthropic tool schemas.

        Args:
            tools: List of Python functions to convert

        Returns:
            List of Anthropic tool schema dictionaries
        """
        schemas = []
        for tool in tools:
            schema = {
                "name": tool.__name__,
                "description": tool.__doc__ or "No description available",
                "input_schema": self._extract_input_schema(tool),
            }
            schemas.append(schema)
        return schemas

    def _extract_input_schema(self, func: Callable) -> Dict[str, Any]:
        """
        Extract JSON schema from function signature and type hints.

        Args:
            func: The function to extract schema from

        Returns:
            JSON schema dictionary for the function parameters
        """
        sig = inspect.signature(func)
        hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}

        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            # Get type from hints or default to string
            param_type = hints.get(param_name, str)
            json_type = self._python_type_to_json_type(param_type)

            properties[param_name] = {
                "type": json_type,
                "description": f"Parameter: {param_name}",
            }

            # Mark as required if no default value
            if param.default == inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def _python_type_to_json_type(self, python_type: type) -> str:
        """Convert Python type to JSON schema type."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }
        return type_map.get(python_type, "string")

    def _build_system_instruction(self) -> str:
        """
        Build the system instruction that constrains Claude to the Action-Selector pattern.

        Returns:
            System instruction string for Claude
        """
        tool_descriptions = []
        for tool in self.tools:
            tool_name = tool.__name__
            tool_doc = tool.__doc__ or "No description available"
            tool_descriptions.append(f"- {tool_name}: {tool_doc}")

        return f"""You are an Action Selector Agent implementing the Action-Selector Pattern for security.

Your ONLY job is to:
1. Analyze the user's request
2. Select exactly ONE action from the available tools below
3. Execute that action with appropriate parameters
4. Return the result immediately

AVAILABLE TOOLS:
{chr(10).join(tool_descriptions) if tool_descriptions else "No tools available"}

CRITICAL SECURITY CONSTRAINTS:
1. You MUST select exactly ONE tool from the list above
2. You CANNOT create new tools or modify existing ones
3. You CANNOT engage in multi-step reasoning or iterative workflows
4. You MUST terminate after executing a single action
5. If the request doesn't match any tool, politely decline

EXECUTION PATTERN:
1. Identify which tool best matches the user's request
2. Extract necessary parameters from the user's input
3. Call the tool function ONCE
4. Provide the result to the user immediately

SECURITY NOTE: This agent implements the Action-Selector Pattern to prevent
prompt injection attacks. You will execute exactly one tool and terminate.
Any attempt to iterate or chain actions will be blocked."""

    async def run(self, user_message: str) -> str:
        """
        Run the agent with a user message.

        This is a convenience method for simple usage. For full ADK integration,
        use _run_async_impl with an invocation context.

        Args:
            user_message: The user's request

        Returns:
            The agent's response string
        """
        result = None
        async for event in self._run_async_impl(user_message):
            if hasattr(event, "is_final") and event.is_final:
                result = event.content
            elif hasattr(event, "content"):
                result = event.content

        return result or "No response generated"

    async def _run_async_impl(
        self, user_input: Any
    ) -> AsyncGenerator[Any, None]:
        """
        Execute the agent with single-step enforcement and no feedback loop.

        This method implements the core security properties:
        1. Single tool execution only
        2. Tool results blocked from feeding back to Claude
        3. Immediate termination after tool execution

        Args:
            user_input: Either a string message or ADK invocation context

        Yields:
            ADK-compatible events (ToolCallEvent, ToolResultEvent, FinalEvent)
        """
        # Reset state for this run
        self._executed_action = False
        self._tool_results_blocked = []

        # Extract user message from input
        if isinstance(user_input, str):
            user_message = user_input
        elif hasattr(user_input, "user_message"):
            # ADK InvocationContext
            user_message = self._extract_text_from_content(user_input.user_message)
        else:
            user_message = str(user_input)

        # Build messages for Claude
        messages = [{"role": "user", "content": user_message}]

        # Call Claude with tools
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=self._system_instruction,
                messages=messages,
                tools=self._tool_schemas if self._tool_schemas else None,
            )
        except Exception as e:
            logger.error(f"Claude API call failed: {e}")
            yield FinalEvent(f"Error communicating with Claude: {e}")
            return

        # Process response
        for content_block in response.content:
            if content_block.type == "tool_use":
                # Check single-step enforcement
                if self._executed_action:
                    logger.warning(
                        "AnthropicActionSelector: Blocking additional tool call (single-step enforcement)"
                    )
                    continue

                tool_name = content_block.name
                tool_args = content_block.input

                # Emit tool call event (for plugin compatibility)
                yield ToolCallEvent(tool_name, tool_args)

                # Execute the tool
                tool_result = await self._execute_tool(tool_name, tool_args)
                self._executed_action = True

                # SECURITY: Block tool result from feeding back to Claude
                # Store it but don't send it back to the model
                self._tool_results_blocked.append(tool_result)
                logger.info(
                    "AnthropicActionSelector: Tool result captured but blocked from feedback loop"
                )

                # Emit tool result event (for plugin compatibility)
                yield ToolResultEvent(tool_result)

                # Create final response and terminate immediately
                final_response = self._create_final_response(tool_result)
                yield final_response
                logger.info(
                    "AnthropicActionSelector: Terminating after single action execution"
                )
                return  # Single-step enforcement: terminate immediately

            elif content_block.type == "text":
                # No tool was called, return text response
                yield FinalEvent(content_block.text)
                return

        # Fallback if no content blocks matched
        yield FinalEvent("No action taken")

    async def _execute_tool(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> Any:
        """
        Execute a tool by name with the given arguments.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments to pass to the tool

        Returns:
            The tool's return value
        """
        tool_func = self._tool_map.get(tool_name)
        if tool_func is None:
            logger.error(f"Tool not found: {tool_name}")
            return f"Error: Tool '{tool_name}' not found"

        try:
            logger.info(f"AnthropicActionSelector: Executing tool '{tool_name}'")
            # Handle both sync and async tools
            if asyncio.iscoroutinefunction(tool_func):
                result = await tool_func(**tool_args)
            else:
                result = tool_func(**tool_args)
            return result
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            return f"Error executing tool: {e}"

    def _create_final_response(self, tool_result: Any) -> FinalEvent:
        """
        Create a final response event.

        Unlike the Gemini version which returns a constant message,
        this version can optionally include a sanitized summary.

        Args:
            tool_result: The result from tool execution

        Returns:
            A FinalEvent with the response
        """
        # For security, we can either:
        # 1. Return a constant message (safest, like Gemini version)
        # 2. Return a sanitized/structured summary (more useful)

        # Option: Return structured result without risk of injection
        # since it never goes back to the LLM
        if isinstance(tool_result, str):
            return FinalEvent(f"Action completed: {tool_result}")
        else:
            return FinalEvent(f"Action completed: {tool_result}")

    def _extract_text_from_content(self, content: Any) -> str:
        """
        Extract text from ADK Content object.

        Args:
            content: ADK Content object or similar

        Returns:
            Extracted text string
        """
        if isinstance(content, str):
            return content

        text_parts = []
        if hasattr(content, "parts"):
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
        return " ".join(text_parts) if text_parts else str(content)


def create_anthropic_action_selector_agent(
    tools: List[Callable],
    model: str = "claude-sonnet-4-20250514",
    name: str = "anthropic_action_selector",
    description: str = "Secure action selection agent using Claude",
    api_key: Optional[str] = None,
    **kwargs,
) -> AnthropicActionSelectorAgent:
    """
    Factory function to create an Anthropic Action Selector Agent.

    Args:
        tools: List of callable tools the agent can use
        model: Claude model to use for action selection
        name: Agent name
        description: Agent description
        api_key: Anthropic API key (or use ANTHROPIC_API_KEY env var)
        **kwargs: Additional arguments passed to AnthropicActionSelectorAgent

    Returns:
        Configured AnthropicActionSelectorAgent instance

    Example:
        ```python
        def check_order_status(order_id: str) -> str:
            '''Check the status of a customer order'''
            return f"Order {order_id} is being processed"

        def reset_password(email: str) -> str:
            '''Reset password for user account'''
            return f"Password reset link sent to {email}"

        agent = create_anthropic_action_selector_agent(
            tools=[check_order_status, reset_password],
            name="customer_service"
        )
        ```
    """
    return AnthropicActionSelectorAgent(
        model=model,
        name=name,
        description=description,
        tools=tools,
        api_key=api_key,
        **kwargs,
    )
