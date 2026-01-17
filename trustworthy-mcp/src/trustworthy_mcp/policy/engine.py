"""Policy engine - orchestrates the security pipeline."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Awaitable

from trustworthy_mcp.approval.manager import ApprovalManager, ApprovalStatus
from trustworthy_mcp.approval.cli import format_approval_for_output
from trustworthy_mcp.audit.logger import AuditLogger
from trustworthy_mcp.policy.classifier import InjectionClassifier
from trustworthy_mcp.policy.sanitizer import Sanitizer, OutputSanitizer
from trustworthy_mcp.tools.registry import ToolRegistry, RiskTier

logger = logging.getLogger(__name__)


@dataclass
class PolicyResult:
    """Result of processing a tool call through the policy engine."""
    output: str
    is_error: bool = False
    input_sanitized: bool = False
    output_sanitized: bool = False
    required_approval: bool = False
    approval_id: str | None = None


class PolicyEngine:
    """Orchestrates the security pipeline for tool calls.

    Pipeline stages:
    1. Input sanitization (injection defense)
    2. Risk classification
    3. HITL approval gate (if required)
    4. Tool execution
    5. Output sanitization & audit
    """

    def __init__(
        self,
        registry: ToolRegistry,
        approval_manager: ApprovalManager,
        audit_logger: AuditLogger,
        aws_region: str | None = None,
        enable_injection_detection: bool = True,
        enable_output_sanitization: bool = True,
    ) -> None:
        """Initialize the policy engine.

        Args:
            registry: Tool registry for risk classification
            approval_manager: Manager for HITL approvals
            audit_logger: Logger for audit events
            aws_region: AWS region for Bedrock classifier
            enable_injection_detection: Whether to use LLM-based injection detection
            enable_output_sanitization: Whether to sanitize tool outputs
        """
        self.registry = registry
        self.approval_manager = approval_manager
        self.audit_logger = audit_logger
        self.enable_output_sanitization = enable_output_sanitization

        # Initialize injection classifier if enabled
        classifier = None
        if enable_injection_detection:
            try:
                classifier = InjectionClassifier(aws_region=aws_region)
            except Exception as e:
                logger.warning(f"Could not initialize Bedrock classifier: {e}")

        self.sanitizer = Sanitizer(classifier=classifier)
        self.output_sanitizer = OutputSanitizer()

        # Tool implementations
        self._tool_handlers: dict[str, Callable[..., Awaitable[str]]] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default tool handler implementations."""
        self._tool_handlers = {
            "read_file": self._handle_read_file,
            "list_directory": self._handle_list_directory,
            "search_files": self._handle_search_files,
            "write_file": self._handle_write_file,
            "create_directory": self._handle_create_directory,
            "execute_command": self._handle_execute_command,
            "delete_file": self._handle_delete_file,
            "http_request": self._handle_http_request,
            "check_approval_status": self._handle_check_approval_status,
            "list_pending_approvals": self._handle_list_pending_approvals,
            "approve_request": self._handle_approve_request,
            "deny_request": self._handle_deny_request,
        }

    async def process_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        workspace_path: str,
    ) -> PolicyResult:
        """Process a tool call through the security pipeline.

        Args:
            tool_name: Name of the tool being called
            arguments: Tool arguments
            workspace_path: Root path for sandboxed operations

        Returns:
            PolicyResult with output and metadata
        """
        # Get risk tier
        risk_tier = self.registry.get_risk_tier(tool_name)
        self.audit_logger.log_tool_call(tool_name, arguments, risk_tier.value)

        # Stage 1: Input sanitization
        sanitized_args, sanitization_results = self.sanitizer.sanitize_args(arguments)

        if sanitization_results:
            warnings = []
            for result in sanitization_results:
                warnings.extend(result.warnings)
            self.audit_logger.log_sanitization(tool_name, warnings)

            # Check if we should block
            if self.sanitizer.should_block(sanitization_results):
                for result in sanitization_results:
                    if result.classification:
                        self.audit_logger.log_injection_detected(
                            tool_name,
                            {
                                "risk_score": result.classification.risk_score,
                                "attack_type": result.classification.attack_type.value,
                                "explanation": result.classification.explanation,
                            },
                            blocked=True,
                        )
                return PolicyResult(
                    output="Request blocked: Potential prompt injection detected",
                    is_error=True,
                )

        # Stage 2: Policy validation
        is_valid, error_msg = self.registry.validate_args(tool_name, sanitized_args)
        if not is_valid:
            self.audit_logger.log_policy_violation(tool_name, error_msg or "Policy violation", arguments)
            return PolicyResult(
                output=f"Policy violation: {error_msg}",
                is_error=True,
            )

        # Stage 3: HITL approval gate
        requires_approval = self.registry.requires_approval(tool_name)
        approval_token = sanitized_args.pop("approval_token", None)

        if requires_approval:
            if approval_token:
                # Verify the approval token
                is_valid, error = self.approval_manager.verify_token(
                    approval_token, tool_name, sanitized_args
                )
                if not is_valid:
                    return PolicyResult(
                        output=f"Approval token invalid: {error}",
                        is_error=True,
                    )
                self.audit_logger.log_approval_granted(tool_name, "token_verified")
            else:
                # Create approval request
                approval = self.approval_manager.create_approval_request(
                    tool_name, sanitized_args
                )
                self.audit_logger.log_approval_requested(
                    tool_name, approval.approval_id, sanitized_args
                )
                return PolicyResult(
                    output=format_approval_for_output(approval),
                    is_error=False,
                    required_approval=True,
                    approval_id=approval.approval_id,
                )

        # Stage 4: Tool execution
        handler = self._tool_handlers.get(tool_name)
        if handler is None:
            return PolicyResult(
                output=f"Unknown tool: {tool_name}",
                is_error=True,
            )

        try:
            result = await handler(workspace_path=workspace_path, **sanitized_args)
        except Exception as e:
            self.audit_logger.log_error(tool_name, str(e))
            return PolicyResult(
                output=f"Tool execution error: {e!s}",
                is_error=True,
            )

        # Stage 5: Output sanitization
        output_was_sanitized = False
        if self.enable_output_sanitization:
            result, output_was_sanitized = self.output_sanitizer.sanitize_output(result)
            if output_was_sanitized:
                logger.debug(f"Output sanitization applied for {tool_name}")

        self.audit_logger.log_tool_result(tool_name, result)

        return PolicyResult(
            output=result,
            is_error=False,
            input_sanitized=bool(sanitization_results),
            output_sanitized=output_was_sanitized,
        )

    # -------------------------------------------------------------------------
    # Tool Handler Implementations
    # -------------------------------------------------------------------------

    async def _handle_read_file(
        self, workspace_path: str, path: str, **kwargs: Any
    ) -> str:
        """Read file contents with path sandboxing."""
        full_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, full_path)

        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not full_path.is_file():
            raise ValueError(f"Not a file: {path}")

        content = full_path.read_text()
        # Tag as potentially untrusted if from certain paths
        if any(p in str(full_path) for p in [".git", "node_modules", "vendor"]):
            content = self.output_sanitizer.tag_as_untrusted(content, f"file:{path}")

        return content

    async def _handle_list_directory(
        self, workspace_path: str, path: str, **kwargs: Any
    ) -> str:
        """List directory contents with path sandboxing."""
        full_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, full_path)

        if not full_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        if not full_path.is_dir():
            raise ValueError(f"Not a directory: {path}")

        entries = []
        for entry in sorted(full_path.iterdir()):
            entry_type = "dir" if entry.is_dir() else "file"
            entries.append(f"{entry_type}: {entry.name}")

        return "\n".join(entries) if entries else "(empty directory)"

    async def _handle_search_files(
        self, workspace_path: str, pattern: str, path: str = ".", **kwargs: Any
    ) -> str:
        """Search for files matching a pattern."""
        import glob

        search_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, search_path)

        full_pattern = str(search_path / pattern)
        matches = glob.glob(full_pattern, recursive=True)

        # Filter to workspace and convert to relative paths
        workspace = Path(workspace_path).resolve()
        results = []
        for match in matches[:100]:  # Limit results
            match_path = Path(match).resolve()
            try:
                rel_path = match_path.relative_to(workspace)
                results.append(str(rel_path))
            except ValueError:
                # Path escapes workspace, skip it
                continue

        return "\n".join(results) if results else "No matches found"

    async def _handle_write_file(
        self, workspace_path: str, path: str, content: str, **kwargs: Any
    ) -> str:
        """Write content to a file with path sandboxing."""
        full_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, full_path)

        # Create parent directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)

        full_path.write_text(content)
        return f"Successfully wrote {len(content)} bytes to {path}"

    async def _handle_create_directory(
        self, workspace_path: str, path: str, **kwargs: Any
    ) -> str:
        """Create a directory with path sandboxing."""
        full_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, full_path)

        full_path.mkdir(parents=True, exist_ok=True)
        return f"Successfully created directory: {path}"

    async def _handle_execute_command(
        self, workspace_path: str, command: str, cwd: str | None = None, **kwargs: Any
    ) -> str:
        """Execute a shell command (requires prior approval)."""
        import asyncio

        work_dir = workspace_path
        if cwd:
            work_dir = str(self._resolve_path(workspace_path, cwd))
            self._validate_path_in_workspace(workspace_path, Path(work_dir))

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=work_dir,
        )

        stdout, stderr = await proc.communicate()
        output_parts = []

        if stdout:
            output_parts.append(f"stdout:\n{stdout.decode()}")
        if stderr:
            output_parts.append(f"stderr:\n{stderr.decode()}")

        output_parts.append(f"exit_code: {proc.returncode}")

        result = "\n".join(output_parts)
        # Tag command output as untrusted
        return self.output_sanitizer.tag_as_untrusted(result, f"command:{command[:50]}")

    async def _handle_delete_file(
        self, workspace_path: str, path: str, **kwargs: Any
    ) -> str:
        """Delete a file (requires prior approval)."""
        full_path = self._resolve_path(workspace_path, path)
        self._validate_path_in_workspace(workspace_path, full_path)

        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if full_path.is_dir():
            import shutil
            shutil.rmtree(full_path)
            return f"Successfully deleted directory: {path}"
        else:
            full_path.unlink()
            return f"Successfully deleted file: {path}"

    async def _handle_http_request(
        self,
        workspace_path: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Make an HTTP request (requires prior approval)."""
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
                timeout=30.0,
            )

        result = f"status: {response.status_code}\nheaders: {dict(response.headers)}\nbody:\n{response.text}"
        # Tag HTTP response as untrusted
        return self.output_sanitizer.tag_as_untrusted(result, f"http:{url[:50]}")

    async def _handle_check_approval_status(
        self, workspace_path: str, approval_id: str, **kwargs: Any
    ) -> str:
        """Check the status of a pending approval."""
        approval = self.approval_manager.get_pending(approval_id)

        if approval is None:
            return f"Approval {approval_id} not found"

        status_info = [
            f"Approval ID: {approval.approval_id}",
            f"Status: {approval.status.value}",
            f"Tool: {approval.tool_name}",
            f"Created: {approval.created_at.isoformat()}",
            f"Expires: {approval.expires_at.isoformat()}",
        ]

        if approval.status == ApprovalStatus.APPROVED:
            # Issue a new token for the client to use (approval already granted by human)
            token = self.approval_manager.issue_token(approval_id)
            if token:
                status_info.append(f"\napproval_token: {token.token}")
                status_info.append(f"Token expires: {token.expires_at.isoformat()}")
                status_info.append("\nUse this token in your next tool call to execute the operation.")

        elif approval.status == ApprovalStatus.DENIED:
            status_info.append(f"Denial reason: {approval.denial_reason or 'Not specified'}")

        elif approval.status == ApprovalStatus.EXPIRED:
            status_info.append("This approval has expired. Please submit a new request.")

        return "\n".join(status_info)

    async def _handle_list_pending_approvals(
        self, workspace_path: str, **kwargs: Any
    ) -> str:
        """List all pending approval requests."""
        pending = self.approval_manager.list_pending()

        if not pending:
            return "No pending approvals"

        lines = [f"Pending Approvals ({len(pending)}):", ""]
        for approval in pending:
            lines.append(f"ID: {approval.approval_id}")
            lines.append(f"  Tool: {approval.tool_name}")
            lines.append(f"  Created: {approval.created_at.isoformat()}")
            lines.append(f"  Expires: {approval.expires_at.isoformat()}")
            lines.append(f"  Args: {approval.arguments}")
            lines.append("")

        return "\n".join(lines)

    async def _handle_approve_request(
        self, workspace_path: str, approval_id: str, **kwargs: Any
    ) -> str:
        """Approve a pending request (human operator action)."""
        token = self.approval_manager.approve(approval_id, approved_by="operator")

        if token is None:
            return f"Failed to approve {approval_id}. It may not exist, be expired, or already processed."

        self.audit_logger.log_approval_granted(
            self.approval_manager.get_pending(approval_id).tool_name,
            approval_id,
            "operator",
        )

        return (
            f"Approved {approval_id}\n\n"
            f"approval_token: {token.token}\n"
            f"Token expires: {token.expires_at.isoformat()}\n\n"
            "Use check_approval_status to retrieve the token, or provide "
            "this token directly in the tool call."
        )

    async def _handle_deny_request(
        self, workspace_path: str, approval_id: str, reason: str | None = None, **kwargs: Any
    ) -> str:
        """Deny a pending request (human operator action)."""
        approval = self.approval_manager.get_pending(approval_id)
        if approval is None:
            return f"Approval {approval_id} not found"

        success = self.approval_manager.deny(approval_id, reason)

        if not success:
            return f"Failed to deny {approval_id}. It may already be processed."

        self.audit_logger.log_approval_denied(
            approval.tool_name,
            approval_id,
            reason,
        )

        return f"Denied {approval_id}" + (f": {reason}" if reason else "")

    # -------------------------------------------------------------------------
    # Path Security Utilities
    # -------------------------------------------------------------------------

    def _resolve_path(self, workspace_path: str, path: str) -> Path:
        """Resolve a path relative to the workspace."""
        workspace = Path(workspace_path).resolve()
        if Path(path).is_absolute():
            return Path(path).resolve()
        return (workspace / path).resolve()

    def _validate_path_in_workspace(self, workspace_path: str, path: Path) -> None:
        """Validate that a path is within the workspace.

        Raises:
            ValueError: If path escapes the workspace
        """
        workspace = Path(workspace_path).resolve()
        resolved = path.resolve()

        # Use is_relative_to (Python 3.9+) to avoid prefix bugs like
        # /workspace2 incorrectly matching /workspace
        try:
            resolved.relative_to(workspace)
        except ValueError:
            raise ValueError(
                f"Path '{path}' escapes workspace. "
                f"Operations are restricted to: {workspace}"
            )
