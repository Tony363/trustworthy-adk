"""
Dynamic HITL approval hint generation.

This module provides context-aware hints for human-in-the-loop approval
prompts. Instead of generic "Approve this action?" prompts, it generates
specific hints explaining what the action will do and why approval is needed.

Originally from trustworthy-adk's HITLToolPlugin.
"""

from typing import Optional, Dict, Any, List


# Base hints for common tool types
BASE_HINTS: Dict[str, str] = {
    # File operations
    "read_file": "This will read the contents of a file from disk.",
    "write_file": "This will create or overwrite a file on disk.",
    "delete_file": "This will permanently delete a file.",
    "create_directory": "This will create a new directory.",
    "list_directory": "This will list the contents of a directory.",

    # Command execution
    "execute_command": "This will run a shell command on your system.",
    "run_script": "This will execute a script file.",
    "subprocess": "This will spawn a subprocess.",

    # Network operations
    "http_request": "This will make a network request to an external server.",
    "fetch_url": "This will fetch content from a URL.",
    "send_email": "This will send an email.",
    "webhook": "This will call an external webhook.",

    # Database operations
    "database_query": "This will execute a database query.",
    "database_write": "This will modify data in the database.",

    # System operations
    "system_config": "This will modify system configuration.",
    "install_package": "This will install a software package.",
}


# Risk level descriptions
RISK_DESCRIPTIONS: Dict[int, str] = {
    0: "LOW RISK - Read-only operation with no side effects.",
    1: "MEDIUM RISK - Operation with limited, reversible side effects.",
    2: "HIGH RISK - Operation with significant or irreversible effects.",
}


def generate_approval_hint(
    tool_name: str,
    args: Dict[str, Any],
    risk_tier: int = 1,
    profile: Optional[Any] = None,  # SecurityProfile type
    custom_hints: Optional[Dict[str, str]] = None,
) -> str:
    """
    Generate a context-aware approval hint for a tool call.

    Args:
        tool_name: Name of the tool being called
        args: Arguments passed to the tool
        risk_tier: Risk tier (0=safe, 1=limited, 2=high-risk)
        profile: Optional security profile with session context
        custom_hints: Optional custom hints to override defaults

    Returns:
        Formatted hint string for the approval prompt
    """
    # Get base hint
    hints = {**BASE_HINTS, **(custom_hints or {})}
    base_hint = hints.get(
        tool_name,
        f"This will execute the '{tool_name}' tool."
    )

    # Build the hint
    lines = [base_hint]

    # Add argument details
    arg_details = _format_argument_details(args)
    if arg_details:
        lines.append("")
        lines.append("Details:")
        lines.extend(arg_details)

    # Add risk level
    lines.append("")
    lines.append(f"Risk Level: {RISK_DESCRIPTIONS.get(risk_tier, 'UNKNOWN')}")

    # Add profile context if available
    if profile:
        profile_context = _format_profile_context(profile)
        if profile_context:
            lines.append("")
            lines.append("Session Context:")
            lines.extend(profile_context)

    return "\n".join(lines)


def _format_argument_details(args: Dict[str, Any]) -> List[str]:
    """Format argument details for display."""
    details = []

    # Common argument types with special formatting
    if "command" in args:
        cmd = str(args["command"])
        if len(cmd) > 100:
            cmd = cmd[:100] + "..."
        details.append(f"  Command: {cmd}")

    if "path" in args:
        details.append(f"  Path: {args['path']}")

    if "url" in args:
        details.append(f"  URL: {args['url']}")

    if "content" in args:
        content = str(args["content"])
        if len(content) > 50:
            content = content[:50] + f"... ({len(args['content'])} chars)"
        details.append(f"  Content: {content}")

    if "method" in args:
        details.append(f"  Method: {args['method']}")

    if "body" in args:
        body = str(args["body"])
        if len(body) > 50:
            body = body[:50] + "..."
        details.append(f"  Body: {body}")

    # Add any other args not already shown
    shown_keys = {"command", "path", "url", "content", "method", "body"}
    for key, value in args.items():
        if key not in shown_keys:
            val_str = str(value)
            if len(val_str) > 50:
                val_str = val_str[:50] + "..."
            details.append(f"  {key}: {val_str}")

    return details


def _format_profile_context(profile: Any) -> List[str]:
    """Format security profile context for display."""
    context = []

    # Check for common profile attributes
    if hasattr(profile, "goal_complexity"):
        context.append(f"  Goal Complexity: {profile.goal_complexity}")

    if hasattr(profile, "risk_exposure_score"):
        score = profile.risk_exposure_score
        if isinstance(score, float):
            context.append(f"  Risk Exposure: {score:.2f}")

    if hasattr(profile, "autonomy_level"):
        context.append(f"  Autonomy Level: {profile.autonomy_level}")

    if hasattr(profile, "detection_stats"):
        stats = profile.detection_stats
        if hasattr(stats, "detected_injections") and stats.detected_injections > 0:
            context.append(f"  Injections detected this session: {stats.detected_injections}")

    return context


def format_approval_prompt(
    tool_name: str,
    hint: str,
    options: Optional[List[str]] = None,
) -> str:
    """
    Format a complete approval prompt for CLI display.

    Args:
        tool_name: Name of the tool
        hint: The generated hint
        options: List of available options (default: y/n/v/q)

    Returns:
        Formatted prompt string
    """
    if options is None:
        options = ["[y] Approve", "[n] Deny", "[v] View full args", "[q] Quit"]

    separator = "=" * 60

    lines = [
        "",
        separator,
        f"APPROVAL REQUIRED: {tool_name}",
        separator,
        "",
        hint,
        "",
        separator,
        "Options: " + " | ".join(options),
    ]

    return "\n".join(lines)


def get_denial_reason_prompt() -> str:
    """Get a prompt for requesting denial reason."""
    return "Reason for denial (optional, press Enter to skip): "


def format_denial_message(tool_name: str, reason: Optional[str] = None) -> str:
    """
    Format a message for when a tool call is denied.

    Args:
        tool_name: Name of the denied tool
        reason: Optional reason for denial

    Returns:
        Formatted denial message
    """
    if reason:
        return f"User rejected the request to run {tool_name}. Reason: {reason}"
    return f"User rejected the request to run {tool_name}."
