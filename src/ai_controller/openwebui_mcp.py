"""Register SamiGPT's MCP endpoint with an Open WebUI instance."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

from ..core.config_storage import get_section, update_raw_section
from ..core.logging import get_logger
from ..core.secrets import MASKED_PLACEHOLDER
from ..mcp.supervisor import get_supervisor

logger = get_logger("sami.web.openwebui_mcp")

CONNECTION_ID = "samigpt-mcp"
_activity: Deque[Dict[str, Any]] = deque(maxlen=200)


def _record(level: str, message: str, **details: Any) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "details": details,
    }
    _activity.append(entry)
    getattr(logger, level if level in {"debug", "info", "warning", "error"} else "info")(
        "%s%s",
        message,
        f" | {details}" if details else "",
    )


def activity_log() -> List[Dict[str, Any]]:
    return list(_activity)


def clear_activity_log() -> None:
    _activity.clear()


def record_failure(message: str, error: Exception) -> None:
    _record("error", message, error=str(error))


def _stored_openwebui() -> Dict[str, Any]:
    llm = get_section("llm", {})
    settings = llm.get("openwebui")
    return dict(settings) if isinstance(settings, dict) else {}


def _stored_mcp() -> Dict[str, Any]:
    return dict(get_section("mcp", {}))


def _openwebui_origin(base_url: str) -> str:
    parsed = urlsplit((base_url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Open WebUI base URL must include http:// or https://")
    return f"{parsed.scheme}://{parsed.netloc}"


def _headers(api_key: str) -> Dict[str, str]:
    if not api_key or api_key == MASKED_PLACEHOLDER:
        raise ValueError("Open WebUI API key is not configured")
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _connection(public_url: str, mcp_token: str) -> Dict[str, Any]:
    parsed = urlsplit(public_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Public MCP URL must be an absolute HTTP(S) URL")
    if not parsed.path or parsed.path == "/":
        public_url = public_url.rstrip("/") + "/mcp"
    return {
        "url": public_url,
        "path": "",
        "type": "mcp",
        "auth_type": "bearer",
        "key": mcp_token,
        "headers": None,
        "config": {"enable": True},
        "info": {
            "id": CONNECTION_ID,
            "name": "SamiGPT MCP",
            "description": "SamiGPT SOC investigation tools",
        },
    }


def _is_samigpt(connection: Dict[str, Any]) -> bool:
    return (connection.get("info") or {}).get("id") == CONNECTION_ID


def _safe_connection(connection: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not connection:
        return None
    safe = dict(connection)
    if safe.get("key"):
        safe["key"] = MASKED_PLACEHOLDER
    return safe


async def _request(
    method: str,
    url: str,
    *,
    headers: Dict[str, str],
    json_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(method, url, headers=headers, json=json_data)
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail") or response.text
        except Exception:
            detail = response.text
        raise RuntimeError(f"Open WebUI HTTP {response.status_code}: {str(detail)[:500]}")
    if not response.content:
        return {}
    return response.json()


async def status(*, verify: bool = False, public_url: Optional[str] = None) -> Dict[str, Any]:
    owui = _stored_openwebui()
    mcp = _stored_mcp()
    origin = _openwebui_origin(owui.get("base_url") or "")
    headers = _headers(owui.get("api_key") or "")
    data = await _request(
        "GET",
        f"{origin}/api/v1/configs/tool_servers",
        headers=headers,
    )
    connections = data.get("TOOL_SERVER_CONNECTIONS") or []
    configured = next((item for item in connections if _is_samigpt(item)), None)
    result: Dict[str, Any] = {
        "openwebui_url": origin,
        "configured": configured is not None,
        "connection": _safe_connection(configured),
        "mcp_running": get_supervisor().is_running,
        "connections_count": len(connections),
    }
    if verify:
        candidate = configured or _connection(
            public_url or mcp.get("public_url") or "",
            mcp.get("api_token") or "",
        )
        verified = await _request(
            "POST",
            f"{origin}/api/v1/configs/tool_servers/verify",
            headers=headers,
            json_data=candidate,
        )
        specs = verified.get("specs") or []
        result.update(
            {
                "verified": bool(verified.get("status")),
                "tools_count": len(specs),
                "tools": [item.get("name") for item in specs if isinstance(item, dict)],
            }
        )
    return result


async def connect(public_url: str) -> Dict[str, Any]:
    owui = _stored_openwebui()
    mcp = _stored_mcp()
    origin = _openwebui_origin(owui.get("base_url") or "")
    headers = _headers(owui.get("api_key") or "")
    token = mcp.get("api_token") or ""
    if not token:
        raise ValueError("MCP bearer token is not configured")
    if not get_supervisor().is_running:
        raise RuntimeError("MCP server is not running")

    connection = _connection(public_url, token)
    _record("info", "Verifying Open WebUI can reach SamiGPT MCP", url=public_url)
    verified = await _request(
        "POST",
        f"{origin}/api/v1/configs/tool_servers/verify",
        headers=headers,
        json_data=connection,
    )
    specs = verified.get("specs") or []
    if not verified.get("status"):
        raise RuntimeError("Open WebUI did not verify the MCP connection")
    _record("info", "Open WebUI verified MCP tools", tools_count=len(specs))

    current = await _request(
        "GET",
        f"{origin}/api/v1/configs/tool_servers",
        headers=headers,
    )
    connections = [
        item
        for item in (current.get("TOOL_SERVER_CONNECTIONS") or [])
        if not _is_samigpt(item)
    ]
    connections.append(connection)
    saved = await _request(
        "POST",
        f"{origin}/api/v1/configs/tool_servers",
        headers=headers,
        json_data={"TOOL_SERVER_CONNECTIONS": connections},
    )
    mcp["public_url"] = public_url
    update_raw_section("mcp", mcp)
    llm = dict(get_section("llm", {}))
    openwebui = dict(llm.get("openwebui") or {})
    openwebui["mcp_server_id"] = CONNECTION_ID
    llm["openwebui"] = openwebui
    update_raw_section("llm", llm)
    _record(
        "info",
        "Registered SamiGPT MCP in Open WebUI",
        openwebui_url=origin,
        tools_count=len(specs),
    )
    return {
        "connected": True,
        "verified": True,
        "tools_count": len(specs),
        "tools": [item.get("name") for item in specs if isinstance(item, dict)],
        "connection": _safe_connection(connection),
        "connections_count": len(saved.get("TOOL_SERVER_CONNECTIONS") or connections),
    }


async def disconnect() -> Dict[str, Any]:
    owui = _stored_openwebui()
    origin = _openwebui_origin(owui.get("base_url") or "")
    headers = _headers(owui.get("api_key") or "")
    current = await _request(
        "GET",
        f"{origin}/api/v1/configs/tool_servers",
        headers=headers,
    )
    before = current.get("TOOL_SERVER_CONNECTIONS") or []
    connections = [item for item in before if not _is_samigpt(item)]
    await _request(
        "POST",
        f"{origin}/api/v1/configs/tool_servers",
        headers=headers,
        json_data={"TOOL_SERVER_CONNECTIONS": connections},
    )
    removed = len(before) != len(connections)
    llm = dict(get_section("llm", {}))
    openwebui = dict(llm.get("openwebui") or {})
    openwebui.pop("mcp_server_id", None)
    llm["openwebui"] = openwebui
    update_raw_section("llm", llm)
    _record("info", "Disconnected SamiGPT MCP from Open WebUI", removed=removed)
    return {"connected": False, "removed": removed}


async def provider_mcp_readiness() -> Dict[str, Any]:
    """Return an actionable, secret-free MCP readiness assessment."""
    llm = dict(get_section("llm", {}))
    provider = (llm.get("provider") or "cursor_agent").strip()
    supervisor_status = get_supervisor().status()
    running = bool(supervisor_status.get("running"))
    tools_count = int(supervisor_status.get("tools_count") or 0)

    if not running:
        return {
            "ready": False,
            "severity": "error",
            "code": "mcp_server_stopped",
            "provider": provider,
            "title": "MCP server is stopped",
            "message": (
                "The AI provider cannot use investigation tools. Open MCP Server → "
                "Health & Settings, then start the server."
            ),
            "action_label": "Open MCP Server",
            "action_section": "mcp",
            "tools_count": 0,
        }

    if tools_count == 0:
        return {
            "ready": False,
            "severity": "warning",
            "code": "mcp_no_tools",
            "provider": provider,
            "title": "MCP has no available tools",
            "message": (
                "The MCP listener is running but exposed no tools. Open MCP Server → "
                "Health & Settings to check integrations."
            ),
            "action_label": "Check MCP Server",
            "action_section": "mcp",
            "tools_count": 0,
        }

    if provider != "openwebui":
        return {
            "ready": True,
            "severity": "ok",
            "code": "direct_mcp_ready",
            "provider": provider,
            "title": "MCP tools are ready",
            "message": f"{tools_count} tools are available to the configured AI provider.",
            "tools_count": tools_count,
        }

    openwebui = dict(llm.get("openwebui") or {})
    setup_message = (
        "Open WebUI is not connected to SamiGPT MCP. Go to Settings → LLM → "
        "Open WebUI MCP connection, then select Connect and verify."
    )
    if not (openwebui.get("base_url") and openwebui.get("api_key")):
        return {
            "ready": False,
            "severity": "warning",
            "code": "openwebui_not_configured",
            "provider": provider,
            "title": "Open WebUI provider setup is incomplete",
            "message": (
                "Configure the Open WebUI URL and API key in Settings → LLM, save, "
                "then connect its MCP server."
            ),
            "action_label": "Open LLM Settings",
            "action_section": "settings",
            "action_page": "llm",
            "action_anchor": "openwebui-mcp-card",
            "tools_count": tools_count,
        }

    try:
        remote = await status(verify=False)
    except Exception as e:
        return {
            "ready": False,
            "severity": "error",
            "code": "openwebui_check_failed",
            "provider": provider,
            "title": "Could not verify the Open WebUI MCP connection",
            "message": f"{setup_message} Verification error: {str(e)[:240]}",
            "action_label": "Open connection setup",
            "action_section": "settings",
            "action_page": "llm",
            "action_anchor": "openwebui-mcp-card",
            "tools_count": tools_count,
        }

    registered_id = openwebui.get("mcp_server_id")
    if not (remote.get("configured") and registered_id == CONNECTION_ID):
        return {
            "ready": False,
            "severity": "warning",
            "code": "openwebui_mcp_disconnected",
            "provider": provider,
            "title": "AI provider is not connected to MCP",
            "message": setup_message,
            "action_label": "Connect Open WebUI",
            "action_section": "settings",
            "action_page": "llm",
            "action_anchor": "openwebui-mcp-card",
            "tools_count": tools_count,
        }

    # A registered connection is cheap to query; verify it only in the ready
    # path so the displayed count reflects what Open WebUI can actually see
    # after skill-vector filtering, not the supervisor's unfiltered registry.
    try:
        remote = await status(verify=True)
    except Exception as e:
        return {
            "ready": False,
            "severity": "error",
            "code": "openwebui_mcp_verification_failed",
            "provider": provider,
            "title": "Open WebUI MCP verification failed",
            "message": f"{setup_message} Verification error: {str(e)[:240]}",
            "action_label": "Open connection setup",
            "action_section": "settings",
            "action_page": "llm",
            "action_anchor": "openwebui-mcp-card",
            "tools_count": 0,
        }
    provider_tools_count = int(remote.get("tools_count") or tools_count)
    return {
        "ready": True,
        "severity": "ok",
        "code": "openwebui_mcp_ready",
        "provider": provider,
        "title": "Open WebUI is connected to MCP",
        "message": f"Open WebUI can load {provider_tools_count} SamiGPT investigation tools.",
        "tools_count": provider_tools_count,
        "openwebui_url": remote.get("openwebui_url"),
    }

