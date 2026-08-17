"""MCP HTTPS health endpoint tests."""

from fastapi.testclient import TestClient

from src.mcp.http_server import create_mcp_http_app
from src.mcp.mcp_server import SamiGPTMCPServer

TOKEN = "test-mcp-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_mcp_health_requires_token():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server, api_token=TOKEN)
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/health")
    assert response.status_code == 401


def test_mcp_http_scheme_is_rejected():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server, api_token=TOKEN)
    client = TestClient(app, base_url="http://testserver")
    assert client.get("/health", headers=AUTH).status_code == 403


def test_mcp_health_endpoint():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server, api_token=TOKEN)
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/health", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["server"] == "sami-gpt"
    assert body["transport"] == "https"
    assert body["tools_count"] >= 1
    assert "integrations" in body


def test_mcp_tools_list_endpoint():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server, api_token=TOKEN)
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/tools", headers=AUTH)
    assert response.status_code == 200
    tools = response.json().get("tools") or []
    names = {tool["name"] for tool in tools}
    assert "list_rules" in names
