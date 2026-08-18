import asyncio

from src.ai_controller import openwebui_mcp


class _Supervisor:
    def __init__(self, *, running=True, tools_count=37):
        self._status = {"running": running, "tools_count": tools_count}

    def status(self):
        return dict(self._status)


def _configure(monkeypatch, llm, *, running=True, tools_count=37):
    def get_section(name, default=None):
        if name == "llm":
            return llm
        if name == "mcp":
            return {"api_token": "secret"}
        return default or {}

    monkeypatch.setattr(openwebui_mcp, "get_section", get_section)
    monkeypatch.setattr(
        openwebui_mcp,
        "get_supervisor",
        lambda: _Supervisor(running=running, tools_count=tools_count),
    )


def test_stopped_mcp_points_new_users_to_server_settings(monkeypatch):
    _configure(
        monkeypatch,
        {"provider": "openwebui", "openwebui": {}},
        running=False,
    )

    result = asyncio.run(openwebui_mcp.provider_mcp_readiness())

    assert result["ready"] is False
    assert result["code"] == "mcp_server_stopped"
    assert result["action_section"] == "mcp"
    assert "start the server" in result["message"]


def test_disconnected_openwebui_points_to_exact_connection_panel(monkeypatch):
    _configure(
        monkeypatch,
        {
            "provider": "openwebui",
            "openwebui": {
                "base_url": "http://openwebui:8080",
                "api_key": "key",
            },
        },
    )

    async def remote_status(*, verify=False, public_url=None):
        return {"configured": False, "openwebui_url": "http://openwebui:8080"}

    monkeypatch.setattr(openwebui_mcp, "status", remote_status)

    result = asyncio.run(openwebui_mcp.provider_mcp_readiness())

    assert result["ready"] is False
    assert result["code"] == "openwebui_mcp_disconnected"
    assert result["action_section"] == "settings"
    assert result["action_page"] == "llm"
    assert result["action_anchor"] == "openwebui-mcp-card"
    assert "Settings → LLM → Open WebUI MCP connection" in result["message"]


def test_registered_openwebui_without_provider_mapping_is_not_ready(monkeypatch):
    _configure(
        monkeypatch,
        {
            "provider": "openwebui",
            "openwebui": {
                "base_url": "http://openwebui:8080",
                "api_key": "key",
            },
        },
    )

    async def remote_status(*, verify=False, public_url=None):
        return {"configured": True, "openwebui_url": "http://openwebui:8080"}

    monkeypatch.setattr(openwebui_mcp, "status", remote_status)

    result = asyncio.run(openwebui_mcp.provider_mcp_readiness())

    assert result["ready"] is False
    assert result["code"] == "openwebui_mcp_disconnected"


def test_connected_openwebui_reports_ready_and_tool_count(monkeypatch):
    _configure(
        monkeypatch,
        {
            "provider": "openwebui",
            "openwebui": {
                "base_url": "http://openwebui:8080",
                "api_key": "key",
                "mcp_server_id": openwebui_mcp.CONNECTION_ID,
            },
        },
    )

    async def remote_status(*, verify=False, public_url=None):
        return {"configured": True, "openwebui_url": "http://openwebui:8080"}

    monkeypatch.setattr(openwebui_mcp, "status", remote_status)

    result = asyncio.run(openwebui_mcp.provider_mcp_readiness())

    assert result["ready"] is True
    assert result["code"] == "openwebui_mcp_ready"
    assert result["tools_count"] == 37


def test_non_openwebui_provider_uses_direct_mcp_readiness(monkeypatch):
    _configure(monkeypatch, {"provider": "openai"})

    result = asyncio.run(openwebui_mcp.provider_mcp_readiness())

    assert result["ready"] is True
    assert result["code"] == "direct_mcp_ready"

