"""CLI interface for approval prompts."""

import asyncio
import sys
from typing import Callable

from trustworthy_mcp.approval.manager import ApprovalManager, PendingApproval, ApprovalToken


class CLIApprovalHandler:
    """Handles approval prompts via CLI.

    This runs in a separate thread/process to handle approval requests
    without blocking the MCP server.
    """

    def __init__(self, approval_manager: ApprovalManager) -> None:
        """Initialize the CLI handler.

        Args:
            approval_manager: The approval manager to interact with
        """
        self.manager = approval_manager
        self._approval_callbacks: dict[str, Callable[[bool, str | None], None]] = {}

    def prompt_approval(self, approval: PendingApproval) -> tuple[bool, str | None]:
        """Prompt the user for approval via CLI.

        This is a synchronous blocking call.

        Args:
            approval: The pending approval to prompt for

        Returns:
            Tuple of (approved, denial_reason)
        """
        print("\n" + "=" * 60)
        print(f"APPROVAL REQUIRED: {approval.tool_name}")
        print("=" * 60)
        print(f"Approval ID: {approval.approval_id}")
        print(f"Expires: {approval.expires_at.isoformat()}")
        print("\nArguments:")

        for key, value in approval.arguments.items():
            display_value = value
            if isinstance(value, str):
                if len(value) > 200:
                    display_value = value[:200] + "..."
                # Escape newlines for display
                display_value = display_value.replace("\n", "\\n")
            print(f"  {key}: {display_value}")

        print("\n" + "-" * 60)
        print("Options:")
        print("  [y] Approve this operation")
        print("  [n] Deny this operation")
        print("  [v] View full arguments")
        print("  [q] Quit approval prompt")
        print("-" * 60)

        while True:
            try:
                response = input("\nApprove? [y/n/v/q]: ").strip().lower()

                if response == "y":
                    return True, None
                elif response == "n":
                    reason = input("Denial reason (optional): ").strip() or None
                    return False, reason
                elif response == "v":
                    print("\nFull arguments:")
                    for key, value in approval.arguments.items():
                        print(f"\n{key}:")
                        print(value)
                elif response == "q":
                    return False, "User quit approval prompt"
                else:
                    print("Invalid option. Please enter y, n, v, or q.")

            except EOFError:
                # Non-interactive terminal
                return False, "Non-interactive terminal - cannot prompt for approval"
            except KeyboardInterrupt:
                print("\nApproval cancelled.")
                return False, "User cancelled"

    async def prompt_approval_async(
        self,
        approval: PendingApproval,
    ) -> tuple[bool, str | None]:
        """Async wrapper for approval prompt.

        Runs the blocking prompt in a thread pool executor.

        Args:
            approval: The pending approval to prompt for

        Returns:
            Tuple of (approved, denial_reason)
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.prompt_approval, approval)

    def process_approval(
        self,
        approval: PendingApproval,
    ) -> ApprovalToken | None:
        """Process an approval request through CLI prompt.

        Args:
            approval: The pending approval to process

        Returns:
            ApprovalToken if approved, None if denied
        """
        approved, reason = self.prompt_approval(approval)

        if approved:
            return self.manager.approve(approval.approval_id)
        else:
            self.manager.deny(approval.approval_id, reason)
            return None

    async def process_approval_async(
        self,
        approval: PendingApproval,
    ) -> ApprovalToken | None:
        """Async version of process_approval.

        Args:
            approval: The pending approval to process

        Returns:
            ApprovalToken if approved, None if denied
        """
        approved, reason = await self.prompt_approval_async(approval)

        if approved:
            return self.manager.approve(approval.approval_id)
        else:
            self.manager.deny(approval.approval_id, reason)
            return None


def format_approval_for_output(approval: PendingApproval) -> str:
    """Format a pending approval for MCP tool output.

    This is returned to Claude Code when an operation requires approval.

    Args:
        approval: The pending approval

    Returns:
        Formatted string for MCP response
    """
    return f"""APPROVAL REQUIRED

This operation requires human approval before execution.

Tool: {approval.tool_name}
Approval ID: {approval.approval_id}
Expires: {approval.expires_at.isoformat()}

Arguments:
{_format_args(approval.arguments)}

To approve this operation:
1. Review the arguments above
2. Run the approval CLI or use the check_approval_status tool
3. Re-submit the tool call with the approval_token parameter

The approval will expire in {_minutes_until(approval.expires_at)} minutes."""


def _format_args(args: dict) -> str:
    """Format arguments for display."""
    lines = []
    for key, value in args.items():
        if isinstance(value, str) and len(value) > 100:
            value = value[:100] + "..."
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def _minutes_until(dt) -> int:
    """Calculate minutes until a datetime."""
    from datetime import datetime
    delta = dt - datetime.utcnow()
    return max(0, int(delta.total_seconds() / 60))
