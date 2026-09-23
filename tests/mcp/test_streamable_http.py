from fastapi.testclient import TestClient

from src.mcp.http_server import create_mcp_http_app


class _FakeMCPServer:
    SERVER_VERSION = "test"
    PROTOCOL_VERSION = "2025-06-18"

    class _Logger:
        def info(self, *_args, **_kwargs):
            pass

        def warning(self, *_args, **_kwargs):
            pass

    _mcp_logger = _Logger()

    async def handle_request(self, request):
        if request.get("id") is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"protocolVersion": self.PROTOCOL_VERSION},
        }

    def health_snapshot(self):
        return {"tools_count": 0}


def test_streamable_http_accepts_authenticated_initialize_over_private_http():
    app = create_mcp_http_app(_FakeMCPServer(), "secret", require_https=False)
    client = TestClient(app)

    response = client.post(
        "/mcp",
        headers={"Authorization": "Bearer secret"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["protocolVersion"] == "2025-06-18"
    assert response.headers["mcp-protocol-version"] == "2025-06-18"


def test_streamable_http_rejects_missing_bearer_token():
    app = create_mcp_http_app(_FakeMCPServer(), "secret", require_https=False)
    client = TestClient(app)

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )

    assert response.status_code == 401


def test_streamable_http_notification_returns_accepted():
    app = create_mcp_http_app(_FakeMCPServer(), "secret", require_https=False)
    client = TestClient(app)

    response = client.post(
        "/mcp",
        headers={"Authorization": "Bearer secret"},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )

    assert response.status_code == 202

