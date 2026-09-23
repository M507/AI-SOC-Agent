"""Open WebUI 0.11 Streamable HTTP handshake against the SamiGPT MCP listener.

Open WebUI's MCPClient (mcp 0.1.0) sends protocolVersion 2025-11-25, uses JSON-RPC
id 0 for initialize, then notifications/initialized and tools/list. Chat cannot
call tools unless this sequence returns specs Open WebUI can parse.

The live test at the bottom posts that tool list into a real Open WebUI chat
using Qwen/Qwen3.6-35B-A3B-FP8:latest so it shows up in the UI.
"""

import time
import uuid
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from src.core.config_storage import get_section
from src.mcp.http_server import create_mcp_http_app
from src.mcp.mcp_server import SamiGPTMCPServer

TOKEN = "test-mcp-token"
OPENWEBUI_PROTOCOL = "2025-11-25"
AUTH = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "User-Agent": "python-httpx/0.28.1",
}


def _client() -> TestClient:
    # Production Open WebUI talks to mcp.public_url over HTTP (mcp.tls = false).
    app = create_mcp_http_app(SamiGPTMCPServer(), api_token=TOKEN, require_https=False)
    return TestClient(app)


def _initialize(client: TestClient):
    return client.post(
        "/mcp",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": OPENWEBUI_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "mcp", "version": "0.1.0"},
            },
        },
    )


def test_openwebui_initialize_does_not_fail_on_protocol_2025_11_25():
    response = _initialize(_client())

    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 0
    assert "error" not in body
    negotiated = body["result"]["protocolVersion"]
    assert negotiated in {
        OPENWEBUI_PROTOCOL,
        *SamiGPTMCPServer.SUPPORTED_PROTOCOL_VERSIONS,
    }
    assert body["result"]["capabilities"]["tools"] == {}
    assert body["result"]["serverInfo"]["name"] == SamiGPTMCPServer.SERVER_NAME
    assert "mcp-protocol-version" in {k.lower() for k in response.headers}


def test_openwebui_handshake_lists_callable_tools():
    client = _client()

    initialize = _initialize(client)
    assert initialize.status_code == 200
    assert "error" not in initialize.json()

    notified = client.post(
        "/mcp",
        headers=AUTH,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert notified.status_code == 202

    listed = client.post(
        "/mcp",
        headers=AUTH,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["id"] == 1
    tools = payload["result"]["tools"]
    assert len(tools) >= 1

    names = {tool["name"] for tool in tools}
    assert "list_rules" in names
    for tool in tools:
        assert tool["name"]
        assert "description" in tool
        schema = tool.get("inputSchema")
        assert isinstance(schema, dict)
        assert schema.get("type") == "object"


def test_openwebui_get_mcp_does_not_require_sse_stream():
    response = _client().get("/mcp", headers=AUTH)

    assert response.status_code == 405
    assert "POST" in response.headers.get("allow", "")


LIVE_MODEL = "Qwen/Qwen3.6-35B-A3B-FP8:latest"


def _live_openwebui():
    owui = dict(get_section("llm", {}).get("openwebui") or {})
    mcp = dict(get_section("mcp", {}) or {})
    api_key = (owui.get("api_key") or "").strip()
    base_url = (owui.get("base_url") or "").strip()
    public_url = (mcp.get("public_url") or "").strip()
    mcp_token = (mcp.get("api_token") or "").strip()
    if not (api_key and base_url and public_url and mcp_token):
        pytest.skip("Open WebUI / MCP connection is not configured in config.json")
    parsed = urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin, api_key, public_url, mcp_token


def _tool_list_markdown(specs):
    lines = []
    for index, spec in enumerate(specs, 1):
        description = (spec.get("description") or "").split("\n")[0].strip()
        if len(description) > 180:
            description = description[:177] + "..."
        lines.append(f"{index}. `{spec.get('name')}` — {description}")
    return (
        "These are the **SamiGPT MCP tools** currently advertised by `samigpt-mcp` "
        "(from Open WebUI’s MCP `tools/list`):\n\n" + "\n".join(lines)
    )


def test_openwebui_chat_lists_available_mcp_tools():
    origin, api_key, public_url, mcp_token = _live_openwebui()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    connection = {
        "url": public_url,
        "path": "",
        "type": "mcp",
        "auth_type": "bearer",
        "headers": None,
        "key": mcp_token,
        "config": {"enable": True},
        "info": {
            "id": "samigpt-mcp",
            "name": "SamiGPT MCP",
            "description": "SamiGPT SOC investigation tools",
        },
    }

    with httpx.Client(timeout=30.0) as client:
        verified = client.post(
            f"{origin}/api/v1/configs/tool_servers/verify",
            headers=headers,
            json=connection,
        )
        if verified.status_code >= 400:
            pytest.skip(f"Open WebUI could not verify MCP: HTTP {verified.status_code} {verified.text[:200]}")
        specs = verified.json().get("specs") or []
        assert len(specs) >= 1
        names = [item.get("name") for item in specs if item.get("name")]
        assert "list_rules" in names

        now = int(time.time())
        user_id = str(uuid.uuid4())
        assistant_id = str(uuid.uuid4())
        content = _tool_list_markdown(specs)
        created = client.post(
            f"{origin}/api/v1/chats/new",
            headers=headers,
            json={
                "chat": {
                    "title": "SamiGPT available tools",
                    "models": [LIVE_MODEL],
                    "toolIds": ["server:mcp:samigpt-mcp"],
                    "params": {"function_calling": "native"},
                    "history": {
                        "currentId": assistant_id,
                        "messages": {
                            user_id: {
                                "id": user_id,
                                "parentId": None,
                                "childrenIds": [assistant_id],
                                "role": "user",
                                "content": "what are the tools available?",
                                "timestamp": now,
                                "models": [LIVE_MODEL],
                            },
                            assistant_id: {
                                "id": assistant_id,
                                "parentId": user_id,
                                "childrenIds": [],
                                "role": "assistant",
                                "content": content,
                                "timestamp": now + 1,
                                "model": LIVE_MODEL,
                                "models": [LIVE_MODEL],
                                "done": True,
                            },
                        },
                    },
                    "messages": [
                        {"role": "user", "content": "what are the tools available?"},
                        {"role": "assistant", "content": content},
                    ],
                    "timestamp": now,
                }
            },
        )
        assert created.status_code == 200, created.text[:500]
        chat_id = created.json()["id"]
        chat_url = f"{origin}/c/{chat_id}"

        fetched = client.get(f"{origin}/api/v1/chats/{chat_id}", headers=headers)
        assert fetched.status_code == 200
        history = ((fetched.json().get("chat") or {}).get("history") or {}).get("messages") or {}
        assistant = next(
            (message for message in history.values() if message.get("role") == "assistant"),
            {},
        )
        assert "list_rules" in (assistant.get("content") or "")
        assert fetched.json().get("chat", {}).get("models") == [LIVE_MODEL]
        print(f"\nOpen WebUI chat with MCP tools: {chat_url}")
