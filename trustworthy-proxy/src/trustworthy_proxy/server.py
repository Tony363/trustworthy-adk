"""
ASGI proxy server for trustworthy AI security.

This server sits between Claude Code and the Anthropic API, applying
security features from trustworthy-core to all traffic.

Usage:
    # Start directly
    python -m trustworthy_proxy.server --port 8080

    # Or via CLI
    trustworthy-proxy --port 8080

    # Configure Claude Code
    export ANTHROPIC_BASE_URL=http://localhost:8080
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse, Response
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from trustworthy_proxy.interceptor import RequestInterceptor, ResponseInterceptor
from trustworthy_core.config import get_config

logger = logging.getLogger(__name__)


class ProxyServer:
    """HTTP proxy server for Anthropic API traffic.

    Intercepts requests and responses, applying trustworthy-core
    security features to provide prompt-level protection.
    """

    def __init__(
        self,
        target_url: str = "https://api.anthropic.com",
        enable_request_sanitization: bool = True,
        enable_response_filtering: bool = False,
        risk_threshold: float = 0.7,
        block_high_risk: bool = False,
    ) -> None:
        """Initialize the proxy server.

        Args:
            target_url: Target API URL to proxy to
            enable_request_sanitization: Whether to sanitize requests
            enable_response_filtering: Whether to filter responses
            risk_threshold: Risk score threshold for warnings/blocking
            block_high_risk: Whether to block high-risk requests
        """
        self.target_url = target_url.rstrip("/")
        self.request_interceptor = RequestInterceptor(
            enable_sanitization=enable_request_sanitization,
            risk_threshold=risk_threshold,
            block_high_risk=block_high_risk,
        )
        self.response_interceptor = ResponseInterceptor(
            enable_filtering=enable_response_filtering,
        )

        # Load config overrides
        config = get_config()
        if config.proxy_target_url:
            self.target_url = config.proxy_target_url
        if config.proxy_enable_request_sanitization is not None:
            self.request_interceptor.enable_sanitization = config.proxy_enable_request_sanitization
        if config.proxy_enable_response_filtering is not None:
            self.response_interceptor.enable_filtering = config.proxy_enable_response_filtering

        # HTTP client for forwarding requests
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(300.0),  # 5 minute timeout for long requests
            follow_redirects=True,
        )

    async def proxy_request(self, request: Request) -> Response:
        """Proxy a request to the target API.

        Args:
            request: The incoming request

        Returns:
            Response from the target API (potentially modified)
        """
        # Build target URL
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""
        target = f"{self.target_url}{path}"
        if query:
            target = f"{target}?{query}"

        # Get request body
        body = await request.body()
        body_json = None

        # Process JSON body if present
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type and body:
            try:
                body_json = json.loads(body)

                # Intercept and potentially modify the request
                intercept_result = self.request_interceptor.intercept(body_json)

                if intercept_result.blocked:
                    logger.warning(f"Request blocked: {intercept_result.warnings}")
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": {
                                "type": "security_block",
                                "message": "Request blocked by security policy",
                                "warnings": intercept_result.warnings,
                            }
                        },
                    )

                if intercept_result.modified:
                    logger.info(f"Request modified: {intercept_result.warnings}")
                    body = json.dumps(body_json).encode()

            except json.JSONDecodeError:
                logger.warning("Failed to parse request body as JSON")

        # Forward headers (excluding hop-by-hop headers)
        headers = {}
        excluded_headers = {"host", "connection", "transfer-encoding", "content-length"}
        for key, value in request.headers.items():
            if key.lower() not in excluded_headers:
                headers[key] = value

        # Make the proxied request
        try:
            # Check if streaming is requested
            is_streaming = body_json and body_json.get("stream", False)

            if is_streaming:
                return await self._handle_streaming_request(
                    method=request.method,
                    url=target,
                    headers=headers,
                    content=body,
                )
            else:
                response = await self.client.request(
                    method=request.method,
                    url=target,
                    headers=headers,
                    content=body,
                )

                # Process response
                response_body = response.content
                response_headers = dict(response.headers)

                # Remove hop-by-hop headers from response
                for header in ["transfer-encoding", "connection"]:
                    response_headers.pop(header, None)

                # Intercept response for analysis
                if response.headers.get("content-type", "").startswith("application/json"):
                    try:
                        response_json = response.json()
                        self.response_interceptor.intercept(response_json)
                    except json.JSONDecodeError:
                        pass

                return Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=response_headers,
                )

        except httpx.RequestError as e:
            logger.error(f"Proxy request failed: {e}")
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "type": "proxy_error",
                        "message": f"Failed to reach target API: {str(e)}",
                    }
                },
            )

    async def _handle_streaming_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        content: bytes,
    ) -> StreamingResponse:
        """Handle a streaming request.

        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            content: Request body

        Returns:
            StreamingResponse that proxies the stream
        """
        async def stream_generator():
            async with self.client.stream(
                method=method,
                url=url,
                headers=headers,
                content=content,
            ) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk

                    # Try to extract tool calls from streamed data
                    try:
                        chunk_str = chunk.decode("utf-8")
                        if chunk_str.startswith("data: ") and chunk_str != "data: [DONE]":
                            data = json.loads(chunk_str[6:])
                            self.response_interceptor.intercept(data)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass

        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
        )

    async def health_check(self, request: Request) -> JSONResponse:
        """Health check endpoint.

        Args:
            request: The incoming request

        Returns:
            Health status response
        """
        return JSONResponse({
            "status": "healthy",
            "target": self.target_url,
            "stats": self.request_interceptor.get_stats(),
            "tool_profile": self.response_interceptor.get_tool_profile(),
        })

    async def get_stats(self, request: Request) -> JSONResponse:
        """Get security statistics.

        Args:
            request: The incoming request

        Returns:
            Statistics response
        """
        return JSONResponse({
            "request_stats": self.request_interceptor.get_stats(),
            "tool_profile": self.response_interceptor.get_tool_profile(),
        })

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()


def create_app(
    target_url: str = "https://api.anthropic.com",
    enable_request_sanitization: bool = True,
    enable_response_filtering: bool = False,
    risk_threshold: float = 0.7,
    block_high_risk: bool = False,
) -> Starlette:
    """Create the ASGI application.

    Args:
        target_url: Target API URL
        enable_request_sanitization: Whether to sanitize requests
        enable_response_filtering: Whether to filter responses
        risk_threshold: Risk score threshold
        block_high_risk: Whether to block high-risk requests

    Returns:
        Starlette ASGI application
    """
    proxy = ProxyServer(
        target_url=target_url,
        enable_request_sanitization=enable_request_sanitization,
        enable_response_filtering=enable_response_filtering,
        risk_threshold=risk_threshold,
        block_high_risk=block_high_risk,
    )

    routes = [
        Route("/health", proxy.health_check, methods=["GET"]),
        Route("/stats", proxy.get_stats, methods=["GET"]),
        # Catch-all route for API proxying
        Route("/{path:path}", proxy.proxy_request, methods=["GET", "POST", "PUT", "DELETE", "PATCH"]),
    ]

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        ),
    ]

    async def on_shutdown():
        await proxy.close()

    app = Starlette(
        routes=routes,
        middleware=middleware,
        on_shutdown=[on_shutdown],
    )

    return app


# Default application instance for uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "trustworthy_proxy.server:app",
        host="0.0.0.0",
        port=config.proxy_port,
        reload=False,
    )
