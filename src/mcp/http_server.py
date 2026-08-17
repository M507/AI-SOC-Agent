"""
HTTP transport for the SamiGPT MCP server.

Exposes:
- GET  /health  – process + integration health
- GET  /tools   – registered MCP tools
- POST /rpc     – JSON-RPC 2.0 (initialize, tools/list, tools/call)

Stdio MCP (`python -m src.mcp.mcp_server`) is unchanged for Cursor/Claude.
This HTTP listener is what the web UI health-checks and what Open WebUI /
other HTTP MCP clients can call.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from .mcp_server import SamiGPTMCPServer


def create_mcp_http_app(server: SamiGPTMCPServer) -> FastAPI:
    """Build a standalone FastAPI app wrapping an existing MCP server instance."""
    app = FastAPI(
        title="SamiGPT MCP Server",
        description="HTTP JSON-RPC transport for SamiGPT investigation tools",
        version=SamiGPTMCPServer.SERVER_VERSION,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.mcp_server = server

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        snapshot = server.health_snapshot()
        snapshot["transport"] = "http"
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
    base = f"http://{host}:{port}"
    return {
        "health": f"{base}/health",
        "tools": f"{base}/tools",
        "rpc": f"{base}/rpc",
        "stdio": "python -m src.mcp.mcp_server",
    }
