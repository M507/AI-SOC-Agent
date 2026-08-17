"""MCP HTTP health endpoint tests."""

from fastapi.testclient import TestClient

from src.mcp.http_server import create_mcp_http_app
from src.mcp.mcp_server import SamiGPTMCPServer


def test_mcp_health_endpoint():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["server"] == "sami-gpt"
    assert body["transport"] == "http"
    assert body["tools_count"] >= 1
    assert "integrations" in body


def test_mcp_tools_list_endpoint():
    server = SamiGPTMCPServer()
    app = create_mcp_http_app(server)
    client = TestClient(app)
    response = client.get("/tools")
    assert response.status_code == 200
    tools = response.json().get("tools") or []
    names = {tool["name"] for tool in tools}
    assert "list_rules" in names
