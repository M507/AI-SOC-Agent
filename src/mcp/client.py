"""
Client used by LLM providers to list and call MCP tools.

Prefers the in-process MCP server owned by the supervisor. Falls back to the
HTTP JSON-RPC endpoint when the caller is in another process.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger

logger = get_logger("sami.mcp.client")


class MCPToolClient:
    """Thin adapter over SamiGPTMCPServer.handle_request / HTTPS /rpc."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8082,
        api_token: Optional[str] = None,
        verify: Any = None,
        cluster_id: Optional[str] = None,
        tls: Optional[bool] = None,
    ) -> None:
        if host in {"0.0.0.0", "::", "[::]"}:
            host = "127.0.0.1"
        self.host = host
        self.port = port
        self.api_token = api_token or ""
        self.cluster_id = cluster_id
        if tls is None:
            try:
                from ..core.config_storage import get_section

                tls = bool(get_section("mcp", {}).get("tls", True))
            except Exception:
                tls = True
        self.tls = bool(tls)
        if verify is None:
            from ..core.tls import client_ssl_context

            self.verify = client_ssl_context()
        else:
            self.verify = verify

    async def list_tools(self) -> List[Dict[str, Any]]:
        response = await self._rpc("tools/list", {})
        if not response or "result" not in response:
            return []
        return response["result"].get("tools", [])

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> str:
        response = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if not response:
            return json.dumps({"error": "No response from MCP server"})
        if "error" in response:
            return json.dumps(response["error"])
        result = response.get("result", {})
        content = result.get("content")
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
                else:
                    texts.append(str(item))
            return "\n".join(texts) if texts else json.dumps(result)
        if content is None:
            return json.dumps(result)
        return str(content)

    async def _rpc(self, method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        if self.cluster_id:
            params = dict(params or {})
            meta = dict(params.get("_meta") or {})
            meta["elastic_cluster_id"] = self.cluster_id
            params["_meta"] = meta
            request["params"] = params
        inproc = await self._inprocess(request)
        if inproc is not None:
            return inproc
        return await self._http(request)

    async def _inprocess(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            from .supervisor import get_supervisor

            supervisor = get_supervisor()
            if not supervisor.is_running or supervisor.server is None:
                return None
            return await supervisor.server.handle_request(request)
        except Exception as e:
            logger.debug("In-process MCP call failed, will try HTTP: %s", e)
            return None

    async def _http(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            import httpx
        except ImportError:
            logger.warning("httpx is not installed; cannot call MCP over HTTP")
            return None

        scheme = "https" if self.tls else "http"
        url = f"{scheme}://{self.host}:{self.port}/rpc"
        headers = {}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        try:
            verify = self.verify if self.tls else False
            async with httpx.AsyncClient(timeout=60.0, verify=verify) as client:
                response = await client.post(url, json=request, headers=headers)
                response.raise_for_status()
                if response.status_code == 204:
                    return None
                return response.json()
        except Exception as e:
            logger.warning("HTTPS MCP call to %s failed: %s", url, e)
            return None
