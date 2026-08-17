"""
HTTPS JSON-RPC transport for the SamiGPT MCP server.

Exposes:
- GET  /health  – process + integration health
- GET  /tools   – registered MCP tools
- POST /rpc     – JSON-RPC 2.0 (initialize, tools/list, tools/call)

All routes require `Authorization: Bearer <mcp.api_token>` from config.json.
Stdio MCP (`python -m src.mcp.mcp_server`) is unchanged for Cursor/Claude.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .mcp_server import SamiGPTMCPServer


class MCPTokenMiddleware(BaseHTTPMiddleware):
    """Reject MCP HTTP requests that do not present the configured bearer token."""

    async def dispatch(self, request: Request, call_next):
        if request.url.scheme == "http":
            return JSONResponse(status_code=403, content={"error": "HTTPS is required"})
        expected = getattr(request.app.state, "api_token", "") or ""
        provided = ""
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        if not provided:
            provided = (request.headers.get("x-api-token") or "").strip()
        if not expected or not hmac.compare_digest(
            hashlib.sha256(provided.encode("utf-8")).digest(),
            hashlib.sha256(expected.encode("utf-8")).digest(),
        ):
            return JSONResponse(status_code=401, content={"error": "Unauthorized"})
        return await call_next(request)


class MCPSecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        if "server" in response.headers:
            del response.headers["server"]
        return response


def create_mcp_http_app(server: SamiGPTMCPServer, api_token: str) -> FastAPI:
    """Build a standalone FastAPI app wrapping an existing MCP server instance."""
    app = FastAPI(
        title="SamiGPT MCP Server",
        description="HTTPS JSON-RPC transport for SamiGPT investigation tools",
        version=SamiGPTMCPServer.SERVER_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.mcp_server = server
    app.state.api_token = api_token
    app.add_middleware(MCPSecurityHeadersMiddleware)
    app.add_middleware(MCPTokenMiddleware)

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        snapshot = server.health_snapshot()
        snapshot["transport"] = "https"
        return snapshot

    @app.get("/tools")
    async def list_tools() -> Dict[str, Any]:
        response = await server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        return response.get("result", {"tools": []}) if response else {"tools": []}

    @app.post("/rpc")
    async def rpc(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                },
            )

        if isinstance(body, list):
            results = []
            for item in body:
                result = await server.handle_request(item)
                if result is not None:
                    results.append(result)
            return JSONResponse(content=results)

        result = await server.handle_request(body)
        if result is None:
            return Response(status_code=204)
        return JSONResponse(content=result)

    return app


def describe_mcp_endpoints(host: str, port: int) -> Dict[str, str]:
    """Human-readable connection info for the settings UI."""
    base = f"https://{host}:{port}"
    return {
        "health": f"{base}/health",
        "tools": f"{base}/tools",
        "rpc": f"{base}/rpc",
        "stdio": "python -m src.mcp.mcp_server",
        "auth": "Authorization: Bearer <mcp.api_token from config.json>",
    }
