"""MCP Security Gateway Server.

This server implements trustworthy-adk security patterns for Claude Code:
- Human-in-the-Loop (HITL) approval for sensitive operations
- Prompt injection detection and sanitization
- Audit logging for all tool calls
"""

import asyncio
import logging
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    TextContent,
    Tool,
)

from trustworthy_mcp.approval.manager import ApprovalManager
from trustworthy_mcp.audit.logger import AuditLogger
from trustworthy_mcp.policy.engine import PolicyEngine
from trustworthy_mcp.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class TrustworthyMCPServer:
    """MCP server with security gateway capabilities."""

    def __init__(
        self,
        workspace_path: str | None = None,
        aws_region: str | None = None,
    ) -> None:
        """Initialize the security gateway server.

        Args:
            workspace_path: Root path for sandboxed file operations.
                          Defaults to current working directory.
            aws_region: AWS region for Bedrock injection classifier.
                       Falls back to AWS_REGION env var or us-east-1.
        """
        self.workspace_path = workspace_path or os.getcwd()
        self.aws_region = aws_region or os.environ.get("AWS_REGION", "us-east-1")

        # Initialize components
        self.registry = ToolRegistry()
        self.approval_manager = ApprovalManager()
        self.audit_logger = AuditLogger()
        self.policy_engine = PolicyEngine(
            registry=self.registry,
            approval_manager=self.approval_manager,
            audit_logger=self.audit_logger,
            aws_region=self.aws_region,
        )

        # Create MCP server
        self.server = Server("trustworthy-mcp")
        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register MCP protocol handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools with their schemas."""
            return [
                # Tier 0: Safe operations
                Tool(
                    name="read_file",
                    description="Read the contents of a file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to read",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                Tool(
                    name="list_directory",
                    description="List contents of a directory",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the directory",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                Tool(
                    name="search_files",
                    description="Search for files matching a pattern",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "Glob pattern to match files",
                            },
                            "path": {
                                "type": "string",
                                "description": "Directory to search in",
                                "default": ".",
                            },
                        },
                        "required": ["pattern"],
                    },
                ),
                # Tier 1: Limited side effects
                Tool(
                    name="write_file",
                    description="Write content to a file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to write",
                            },
                            "content": {
                                "type": "string",
                                "description": "Content to write to the file",
                            },
                        },
                        "required": ["path", "content"],
                    },
                ),
                Tool(
                    name="create_directory",
                    description="Create a new directory",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path of the directory to create",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                # Tier 2: High-risk operations (require approval)
                Tool(
                    name="execute_command",
                    description="Execute a shell command (requires approval)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to execute",
                            },
                            "cwd": {
                                "type": "string",
                                "description": "Working directory for the command",
                            },
                            "approval_token": {
                                "type": "string",
                                "description": "Approval token for pre-approved commands",
                            },
                        },
                        "required": ["command"],
                    },
                ),
                Tool(
                    name="delete_file",
                    description="Delete a file (requires approval)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to delete",
                            },
                            "approval_token": {
                                "type": "string",
                                "description": "Approval token for pre-approved deletion",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                Tool(
                    name="http_request",
                    description="Make an HTTP request (requires approval)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "method": {
                                "type": "string",
                                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                                "description": "HTTP method",
                            },
                            "url": {
                                "type": "string",
                                "description": "URL to request",
                            },
                            "headers": {
                                "type": "object",
                                "description": "Request headers",
                            },
                            "body": {
                                "type": "string",
                                "description": "Request body",
                            },
                            "approval_token": {
                                "type": "string",
                                "description": "Approval token for pre-approved requests",
                            },
                        },
                        "required": ["method", "url"],
                    },
                ),
                # Approval management tools
                Tool(
                    name="check_approval_status",
                    description="Check status of a pending approval",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "approval_id": {
                                "type": "string",
                                "description": "The approval ID to check",
                            },
                        },
                        "required": ["approval_id"],
                    },
                ),
                Tool(
                    name="list_pending_approvals",
                    description="List all pending approval requests",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                Tool(
                    name="approve_request",
                    description="Approve a pending request (human operator action)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "approval_id": {
                                "type": "string",
                                "description": "The approval ID to approve",
                            },
                        },
                        "required": ["approval_id"],
                    },
                ),
                Tool(
                    name="deny_request",
                    description="Deny a pending request (human operator action)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "approval_id": {
                                "type": "string",
                                "description": "The approval ID to deny",
                            },
                            "reason": {
                                "type": "string",
                                "description": "Reason for denial",
                            },
                        },
                        "required": ["approval_id"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
            """Handle tool calls through the security pipeline."""
            return await self._handle_tool_call(name, arguments)

    async def _handle_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        """Process a tool call through the security pipeline.

        Pipeline stages:
        1. Input sanitization (injection defense)
        2. Risk classification
        3. HITL approval gate (if required)
        4. Tool execution
        5. Output sanitization & audit
        """
        try:
            # Process through policy engine
            result = await self.policy_engine.process_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                workspace_path=self.workspace_path,
            )

            return CallToolResult(
                content=[TextContent(type="text", text=result.output)],
                isError=result.is_error,
            )

        except Exception as e:
            logger.exception(f"Error processing tool call {tool_name}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error: {e!s}")],
                isError=True,
            )

    async def run(self) -> None:
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


def main() -> None:
    """Entry point for the MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    server = TrustworthyMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
