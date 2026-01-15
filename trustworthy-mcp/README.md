# Trustworthy MCP

An MCP (Model Context Protocol) security gateway that implements [trustworthy-adk](../README.md) security patterns for Claude Code.

## Features

- **Human-in-the-Loop (HITL) Approval**: Requires explicit human approval for high-risk operations (code execution, file deletion, HTTP requests)
- **Prompt Injection Defense**: Detects and sanitizes injection attempts using heuristics and optional LLM-based classification
- **Path Sandboxing**: Restricts file operations to the workspace directory
- **Audit Logging**: Comprehensive logging of all tool calls and security events
- **Risk-Based Classification**: Tools categorized by risk tier (Safe, Limited, High-Risk)

## Installation

```bash
# Install in development mode
cd trustworthy-mcp
uv pip install -e ".[dev]"
```

## Usage with Claude Code

Add to your Claude Code MCP configuration (`~/.claude.json` or project settings):

```json
{
  "mcpServers": {
    "trustworthy": {
      "command": "uv",
      "args": ["run", "trustworthy-mcp"],
      "cwd": "/path/to/trustworthy-mcp",
      "env": {
        "ANTHROPIC_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Architecture

```
Claude Code → MCP Security Gateway → Actual Operations
                    ↓
             Policy Pipeline:
             1. Input sanitization (injection defense)
             2. Risk classification
             3. HITL approval gate (if required)
             4. Tool execution
             5. Output sanitization & audit
```

## Security Patterns

### Risk Tiers

| Tier | Level | Examples | Approval Required |
|------|-------|----------|-------------------|
| 0 | Safe | read_file, list_directory | No |
| 1 | Limited | write_file, create_directory | No |
| 2 | High-Risk | execute_command, delete_file, http_request | Yes |

### HITL Approval Flow

1. High-risk tool call arrives without approval token
2. Gateway creates pending approval and returns approval_id
3. User reviews and approves/denies (via CLI or external system)
4. If approved, user receives approval_token
5. User re-submits tool call with approval_token
6. Gateway verifies token matches exact tool+args and executes

### Injection Defense

Two-layer detection:
1. **Heuristic classifier**: Fast pattern matching for known injection patterns
2. **LLM classifier**: Deep analysis using Claude (optional, requires API key)

Detected patterns are sanitized or blocked based on risk score.

## Available Tools

### Safe (Tier 0)
- `read_file`: Read file contents
- `list_directory`: List directory contents
- `search_files`: Search for files by pattern

### Limited (Tier 1)
- `write_file`: Write content to a file
- `create_directory`: Create a new directory

### High-Risk (Tier 2)
- `execute_command`: Execute shell commands (requires approval)
- `delete_file`: Delete files (requires approval)
- `http_request`: Make HTTP requests (requires approval)

### Management
- `check_approval_status`: Check/retrieve approval tokens

## Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/trustworthy_mcp --cov-report=html

# Run specific test file
uv run pytest tests/test_policy_engine.py -v
```

## Environment Variables

- `ANTHROPIC_API_KEY`: API key for LLM-based injection classification (optional)

## License

MIT
