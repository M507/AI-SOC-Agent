"""
HTTPS JSON-RPC transport for the SamiGPT MCP server.

Exposes:
- GET  /health  – process + integration health
- GET  /tools   – registered MCP tools
- POST /rpc     – JSON-RPC 2.0 (initialize, tools/list, tools/call)
- POST /mcp     – MCP Streamable HTTP transport for Open WebUI and other clients

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
        if request.url.scheme == "http" and getattr(request.app.state, "require_https", True):
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


def create_mcp_http_app(
    server: SamiGPTMCPServer,
    api_token: str,
    *,
    require_https: bool = True,
) -> FastAPI:
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
    app.state.require_https = require_https
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

    @app.post("/mcp")
    async def streamable_http(request: Request):
        """
        Stateless MCP Streamable HTTP endpoint.

        MCP clients send the same JSON-RPC messages as the legacy /rpc route.
        A JSON response is valid when the client advertises application/json;
        notifications receive 202 Accepted. Keeping this endpoint stateless
        avoids leaking sessions between Open WebUI users.
        """
        client = request.client.host if request.client else "unknown"
        user_agent = (request.headers.get("user-agent") or "unknown")[:200]
        try:
            body = await request.json()
        except Exception:
            server._mcp_logger.warning(
                "STREAMABLE_HTTP invalid JSON client=%s user_agent=%s",
                client,
                user_agent,
            )
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                },
            )

        method = body.get("method") if isinstance(body, dict) else "batch"
        server._mcp_logger.info(
            "STREAMABLE_HTTP request client=%s method=%s user_agent=%s",
            client,
            method,
            user_agent,
        )
        requested_version = request.headers.get("mcp-protocol-version")
        if isinstance(body, dict) and body.get("method") == "initialize":
            requested_version = (body.get("params") or {}).get("protocolVersion")
        headers = {
            "MCP-Protocol-Version": (
                requested_version
                or getattr(server, "PROTOCOL_VERSION", SamiGPTMCPServer.PROTOCOL_VERSION)
            )
        }

        if isinstance(body, list):
            results = []
            for item in body:
                result = await server.handle_request(item)
                if result is not None:
                    results.append(result)
            if not results:
                return Response(status_code=202, headers=headers)
            return JSONResponse(content=results, headers=headers)

        result = await server.handle_request(body)
        if result is None:
            return Response(status_code=202, headers=headers)
        return JSONResponse(content=result, headers=headers)

    @app.get("/mcp")
    async def streamable_http_get():
        # This server does not retain SSE streams; clients should use POST.
        return JSONResponse(
            status_code=405,
            content={"error": "SSE streams are not supported; use MCP Streamable HTTP POST"},
            headers={"Allow": "POST, DELETE"},
        )

    @app.delete("/mcp")
    async def streamable_http_delete():
        # Stateless transport has no server-side session to terminate.
        return Response(status_code=204)

    return app


def describe_mcp_endpoints(host: str, port: int, *, tls: bool = True) -> Dict[str, str]:
    """Human-readable connection info for the settings UI."""
    base = f"{'https' if tls else 'http'}://{host}:{port}"
    return {
        "health": f"{base}/health",
        "tools": f"{base}/tools",
        "rpc": f"{base}/rpc",
        "mcp": f"{base}/mcp",
        "stdio": "python -m src.mcp.mcp_server",
        "auth": "Authorization: Bearer <mcp.api_token from config.json>",
    }
