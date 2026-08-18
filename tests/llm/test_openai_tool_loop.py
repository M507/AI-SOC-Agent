import asyncio
import json

import httpx
import pytest

from src.llm import openai_compatible
from src.llm.openai_compatible import (
    OpenAICompatibleProvider,
    mcp_tools_to_catalog,
    parse_text_tool_calls,
)
from src.mcp.client import MCPToolClient


@pytest.fixture(autouse=True)
def clear_route_cache():
    openai_compatible._TOOL_ROUTE_CACHE.clear()
    yield
    openai_compatible._TOOL_ROUTE_CACHE.clear()


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"choices": [{"message": {"content": "ok"}}]}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _AsyncCM:
    def __init__(self, inner):
        self.inner = inner

    async def __aenter__(self):
        return self.inner

    async def __aexit__(self, *_args):
        return None


class _RecordingClient:
    def __init__(self, passthrough_status=403, chat_payloads=None):
        self.passthrough_status = passthrough_status
        self.chat_payloads = list(chat_payloads or [])
        self.calls = []

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "json": json})
        body = json or {}
        if "/openai/v1/" in url and "tools" not in body:
            return _Response(status_code=self.passthrough_status, payload={"detail": "probe"})
        if self.chat_payloads:
            return _Response(payload=self.chat_payloads.pop(0))
        return _Response()


class _FakeMCP:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [
            {
                "name": "get_ip_address_report",
                "description": "Retrieve an aggregated report about an IP address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"ip": {"type": "string"}},
                    "required": ["ip"],
                },
            }
        ]

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments or {}))
        return json.dumps({"ip": (arguments or {}).get("ip"), "malicious": False})


def test_parse_text_tool_calls_reads_xml_blocks():
    text = (
        'I will look that up.\n'
        '<tool_call>{"name": "get_ip_address_report", "arguments": {"ip": "1.1.1.1"}}</tool_call>'
    )
    calls = parse_text_tool_calls(text)
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "get_ip_address_report"
    assert json.loads(calls[0]["function"]["arguments"]) == {"ip": "1.1.1.1"}


def test_parse_text_tool_calls_reads_qwen_name_and_args():
    text = (
        "<tool_call>\n"
        "get_ip_address_report\n"
        '{"ip": "8.8.8.8"}\n'
        "</tool_call>"
    )
    calls = parse_text_tool_calls(text)
    assert calls[0]["function"]["name"] == "get_ip_address_report"
    assert json.loads(calls[0]["function"]["arguments"]) == {"ip": "8.8.8.8"}


def test_catalog_includes_required_arguments():
    catalog = mcp_tools_to_catalog(
        [
            {
                "name": "get_ip_address_report",
                "description": "IP report",
                "inputSchema": {"required": ["ip"]},
            }
        ]
    )
    assert "get_ip_address_report" in catalog
    assert "args: ip" in catalog


def test_wildcard_mcp_bind_is_rewritten_for_clients():
    client = MCPToolClient(host="0.0.0.0", port=8082, tls=False, verify=False)
    assert client.host == "127.0.0.1"


def test_openwebui_without_passthrough_injects_catalog_and_runs_mcp(monkeypatch):
    recorder = _RecordingClient(
        passthrough_status=403,
        chat_payloads=[
            {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '<tool_call>{"name": "get_ip_address_report", '
                                '"arguments": {"ip": "1.1.1.1"}}</tool_call>'
                            )
                        }
                    }
                ]
            },
            {"choices": [{"message": {"content": "1.1.1.1 is Cloudflare DNS, not malicious."}}]},
        ],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    mcp = _FakeMCP()
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {
            "base_url": "http://webui:8080/",
            "model": "Qwen/Qwen3.6-35B-A3B-FP8:latest",
            "mcp_server_id": "samigpt-mcp",
        },
    )

    result = asyncio.run(provider.complete("Is 1.1.1.1 malicious?", mcp_client=mcp))

    chat_calls = [call for call in recorder.calls if call["url"].endswith("/api/v1/chat/completions")]
    assert chat_calls
    first_payload = chat_calls[0]["json"]
    assert "tool_ids" not in first_payload
    assert "tools" not in first_payload
    system = first_payload["messages"][0]["content"]
    assert "get_ip_address_report" in system
    assert "<tool_call>" in system
    assert mcp.calls == [("get_ip_address_report", {"ip": "1.1.1.1"})]
    assert result.success
    assert result.tool_calls == 1
    assert result.tools_advertised == 1
    assert result.tools_supported is True
    assert "Cloudflare" in result.text


def test_passthrough_still_sends_native_openai_tools(monkeypatch):
    recorder = _RecordingClient(
        passthrough_status=200,
        chat_payloads=[{"choices": [{"message": {"content": "done"}}]}],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )

    result = asyncio.run(provider.complete("hello", mcp_client=_FakeMCP()))

    native = [call for call in recorder.calls if "/openai/v1/" in call["url"] and "tools" in (call["json"] or {})]
    assert native
    assert native[0]["json"]["tools"][0]["function"]["name"] == "get_ip_address_report"
    assert result.tools_supported is True
    assert result.tool_calls == 0


def test_passthrough_still_executes_xml_tool_calls_in_content(monkeypatch):
    recorder = _RecordingClient(
        passthrough_status=200,
        chat_payloads=[
            {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '<tool_call>{"name": "get_ip_address_report", '
                                '"arguments": {"ip": "1.1.1.1"}}</tool_call>'
                            )
                        }
                    }
                ]
            },
            {"choices": [{"message": {"content": "clean"}}]},
        ],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    mcp = _FakeMCP()
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )

    result = asyncio.run(provider.complete("hello", mcp_client=mcp))

    assert mcp.calls == [("get_ip_address_report", {"ip": "1.1.1.1"})]
    assert result.tool_calls == 1
    assert result.text == "clean"
