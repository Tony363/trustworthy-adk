"""
Trustworthy Proxy - API proxy for AI security.

This package provides an HTTP proxy that intercepts Claude Code <-> Anthropic API
traffic for prompt-level sanitization. It enables full SoftInstructionDefense
capabilities for Claude Code users.

Usage:
    # Start the proxy server
    trustworthy-proxy --port 8080

    # Configure Claude Code to use the proxy
    export ANTHROPIC_BASE_URL=http://localhost:8080
    claude

Architecture:
    ┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
    │  Claude Code │────▶│  trustworthy-proxy  │────▶│  Anthropic API   │
    │     CLI      │◀────│  (localhost:8080)   │◀────│  api.anthropic.com│
    └──────────────┘     └─────────────────────┘     └──────────────────┘
                                  │
                                  ▼
                         ┌─────────────────────┐
                         │  trustworthy-core   │
                         │  - Prompt sanitizer │
                         │  - 4D Profiler      │
                         │  - Stats tracker    │
                         └─────────────────────┘
"""

from trustworthy_proxy.server import ProxyServer, create_app
from trustworthy_proxy.interceptor import (
    RequestInterceptor,
    ResponseInterceptor,
    InterceptResult,
)

__version__ = "0.1.0"

__all__ = [
    "ProxyServer",
    "create_app",
    "RequestInterceptor",
    "ResponseInterceptor",
    "InterceptResult",
    "__version__",
]
