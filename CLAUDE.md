# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Trustworthy ADK is a Python library providing security-focused extensions for Google's Agent Development Kit (ADK). It implements defensive patterns to protect AI agents from prompt injection attacks and other security threats.

## Common Commands

```bash
# Install in development mode
uv pip install -e ".[dev]"

# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_action_selector_agent.py -v

# Run with coverage
uv run pytest --cov=src/trustworthy --cov-report=html

# Format code
uv run black src/ tests/

# Lint
uv run ruff check src/ tests/

# Type checking
uv run mypy src/
```

## Architecture

### Core Components

The library extends Google ADK's `LlmAgent` and `BasePlugin` classes:

**Agents** (`src/trustworthy/agents/`):
- `ActionSelectorAgent`: Extends `LlmAgent` to implement the Action-Selector Pattern - enforces single-step execution, blocks tool result feedback to prevent Indirect Prompt Injection (IPI)

**Plugins** (`src/trustworthy/plugins/`):
- `HITLToolPlugin`: Extends `BasePlugin`, intercepts tool calls via `before_tool_callback` to require human approval for sensitive operations
- `SoftInstructionDefensePlugin`: Extends `BasePlugin`, intercepts user messages via `on_user_message_callback` to apply iterative sanitization using LLM-based injection detection

### Plugin Integration Pattern

Plugins integrate with ADK runners (e.g., `InMemoryRunner`):
```python
from google.adk.runners import InMemoryRunner
runner = InMemoryRunner(agent=agent, plugins=[your_plugin])
```

### Key ADK Types Used

- `google.adk.agents.LlmAgent` - base agent class
- `google.adk.plugins.BasePlugin` - base plugin class with callbacks
- `google.adk.runners.InMemoryRunner` - runner for executing agents
- `google.genai.types.Content` / `types.Part` - message content structures

### Analysis Tools

`src/trustworthy/analysis/agentic_profiler/` - CLI tool for visualizing agent security posture via radar charts

## Testing

Tests use pytest with async support (`pytest-asyncio`). Mock fixtures for Google AI client responses are defined in `tests/conftest.py`.

## Example Implementation

See `examples/workspace/` for a complete example of using `SoftInstructionDefensePlugin` with an ADK agent that has email and calendar tools.
