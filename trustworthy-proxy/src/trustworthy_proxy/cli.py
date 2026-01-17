"""
Command-line interface for the trustworthy proxy.

Usage:
    trustworthy-proxy --port 8080
    trustworthy-proxy --port 8080 --target https://api.anthropic.com
    trustworthy-proxy --port 8080 --block-high-risk
"""

import argparse
import logging
import sys

import uvicorn

from trustworthy_proxy.server import create_app
from trustworthy_core.config import get_config


def setup_logging(verbose: bool = False) -> None:
    """Configure logging.

    Args:
        verbose: Whether to enable verbose logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description="Trustworthy Proxy - Security gateway for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start proxy on default port
    trustworthy-proxy

    # Start on custom port
    trustworthy-proxy --port 8080

    # Block high-risk requests instead of just sanitizing
    trustworthy-proxy --block-high-risk

    # Configure Claude Code to use the proxy
    export ANTHROPIC_BASE_URL=http://localhost:8080
    claude
        """,
    )

    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: 8080 or TRUSTWORTHY_PROXY_PORT)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Target API URL (default: https://api.anthropic.com)",
    )
    parser.add_argument(
        "--no-sanitize",
        action="store_true",
        help="Disable request sanitization (log only)",
    )
    parser.add_argument(
        "--block-high-risk",
        action="store_true",
        help="Block high-risk requests instead of sanitizing",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=0.7,
        help="Risk score threshold for warnings/blocking (default: 0.7)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Load config
    config = get_config()

    # Determine settings
    port = args.port or config.proxy_port
    target = args.target or config.proxy_target_url
    enable_sanitization = not args.no_sanitize

    logger.info("=" * 60)
    logger.info("Trustworthy Proxy - Security Gateway for Claude Code")
    logger.info("=" * 60)
    logger.info(f"Target API: {target}")
    logger.info(f"Listening on: {args.host}:{port}")
    logger.info(f"Request sanitization: {'enabled' if enable_sanitization else 'disabled'}")
    logger.info(f"Block high-risk: {args.block_high_risk}")
    logger.info(f"Risk threshold: {args.risk_threshold}")
    logger.info("")
    logger.info("To use with Claude Code:")
    logger.info(f"  export ANTHROPIC_BASE_URL=http://localhost:{port}")
    logger.info("  claude")
    logger.info("=" * 60)

    # Create application
    app = create_app(
        target_url=target,
        enable_request_sanitization=enable_sanitization,
        enable_response_filtering=False,
        risk_threshold=args.risk_threshold,
        block_high_risk=args.block_high_risk,
    )

    # Run server
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=port,
            reload=args.reload,
            log_level="debug" if args.verbose else "info",
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
