import asyncio
import json

import httpx
import pytest

from src.llm import openai_compatible
from src.llm.openai_compatible import (
    OpenAICompatibleProvider,
    llm_error_message,
    mcp_tools_to_catalog,
    parse_text_tool_calls,
    visible_agent_text,
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


def test_visible_agent_text_drops_tool_call_markup():
    text = 'I will look that up.\n<tool_call>{"name": "get_ip_address_report"}</tool_call>'
    assert visible_agent_text(text) == "I will look that up."


def test_complete_records_thinking_and_mcp_trace(monkeypatch):
    recorder = _RecordingClient(
        passthrough_status=403,
        chat_payloads=[
            {
                "choices": [
                    {
                        "message": {
                            "reasoning_content": "The IP needs a report before I decide.",
                            "content": (
                                "I'll pull the IP report.\n"
                                '<tool_call>{"name": "get_ip_address_report", '
                                '"arguments": {"ip": "1.1.1.1"}}</tool_call>'
                            ),
                        }
                    }
                ]
            },
            {"choices": [{"message": {"content": "1.1.1.1 is not malicious."}}]},
        ],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    mcp = _FakeMCP()
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )

    result = asyncio.run(provider.complete("Is 1.1.1.1 malicious?", mcp_client=mcp))

    assert result.success
    assert result.text == "1.1.1.1 is not malicious."
    assert [step["kind"] for step in result.trace] == ["status", "think", "tool", "status"]
    assert result.trace[0]["text"].startswith("Asking the model · round 1")
    assert "IP needs a report" in result.trace[1]["text"]
    assert "I'll pull the IP report." in result.trace[1]["text"]
    assert "<tool_call>" not in result.trace[1]["text"]
    assert result.trace[2]["name"] == "get_ip_address_report"
    assert result.trace[2]["phase"] == "done"
    assert result.trace[2]["arguments"] == {"ip": "1.1.1.1"}
    assert "malicious" in result.trace[2]["result"]
    assert result.to_output_dict()["trace"][2]["name"] == "get_ip_address_report"


def test_complete_emits_trace_before_the_final_answer(monkeypatch):
    recorder = _RecordingClient(
        passthrough_status=403,
        chat_payloads=[
            {
                "choices": [
                    {
                        "message": {
                            "content": (
                                "Checking the IP.\n"
                                '<tool_call>{"name": "get_ip_address_report", '
                                '"arguments": {"ip": "1.1.1.1"}}</tool_call>'
                            )
                        }
                    }
                ]
            },
            {"choices": [{"message": {"content": "done"}}]},
        ],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    seen = []

    async def on_trace(trace):
        seen.append([
            (step.get("kind"), step.get("phase"), step.get("text", ""))
            for step in trace
        ])

    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )
    result = asyncio.run(
        provider.complete("look up 1.1.1.1", mcp_client=_FakeMCP(), on_trace=on_trace)
    )

    assert result.text == "done"
    assert ("status", None, "Asking the model · round 1 of 12") in seen[0]
    running = next(i for i, snap in enumerate(seen) if ("tool", "running", "") in snap)
    finished = next(i for i, snap in enumerate(seen) if any(item[0] == "tool" and item[1] == "done" for item in snap))
    assert running < finished
    assert any(("think", None, "") in [(k, p, "") for k, p, _text in snap] for snap in seen[:running])


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


def test_timeout_error_is_not_blank():
    class ReadTimeout(Exception):
        def __str__(self):
            return ""

    assert llm_error_message(ReadTimeout(), 120) == "The model did not respond within 120s"


def test_tool_results_sent_back_to_the_model_are_clipped(monkeypatch):
    class _HugeMCP(_FakeMCP):
        async def call_tool(self, name, arguments=None):
            self.calls.append((name, arguments or {}))
            return "A" * 20000

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
            {"choices": [{"message": {"content": "done"}}]},
        ],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )

    result = asyncio.run(provider.complete("look up", mcp_client=_HugeMCP()))

    assert result.success
    followups = [
        call for call in recorder.calls
        if call["url"].endswith("/api/v1/chat/completions") and len(call["json"]["messages"]) > 2
    ]
    assert followups
    blob = json.dumps(followups[0]["json"]["messages"])
    assert "A" * 9000 not in blob
    assert "\\u2026" in blob


class _TimeoutThenOk(_RecordingClient):
    def __init__(self):
        super().__init__(
            passthrough_status=403,
            chat_payloads=[{"choices": [{"message": {"content": "finished"}}]}],
        )
        self.timeouts = 0

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "json": json})
        if "/openai/v1/" in url and "tools" not in (json or {}):
            return _Response(status_code=403, payload={"detail": "probe"})
        if self.timeouts < 1:
            self.timeouts += 1

            class ReadTimeout(Exception):
                def __str__(self):
                    return ""

            raise ReadTimeout()
        return _Response(payload=self.chat_payloads.pop(0))


def test_llm_timeout_is_retried_once(monkeypatch):
    recorder = _TimeoutThenOk()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(recorder))
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m"},
    )

    result = asyncio.run(provider.complete("hello"))

    assert result.success
    assert result.text == "finished"
    assert recorder.timeouts == 1


class _SSEResponse:
    def __init__(self, pieces):
        self.pieces = pieces
        self.status_code = 200
        self.headers = {"content-type": "text/event-stream"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for piece in self.pieces:
            yield "data: " + json.dumps({"choices": [{"delta": {"content": piece}}]})
        yield "data: [DONE]"


class _StreamClient(_RecordingClient):
    def __init__(self):
        super().__init__(passthrough_status=403, chat_payloads=[])
        self.streams = [
            [
                "Checking the IP.\n",
                '<tool_call>{"name": "get_ip_address_report", "arguments": {"ip": "1.1.1.1"}}</tool_call>',
            ],
            ["1.1.1.1 is clean."],
        ]

    def stream(self, method, url, headers=None, json=None):
        self.calls.append({"url": url, "json": json, "stream": True})
        return _SSEResponse(self.streams.pop(0))


def test_streaming_reply_appears_in_thinking_before_the_tool(monkeypatch):
    client = _StreamClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(client))
    seen = []

    async def on_trace(trace):
        seen.append([
            step.get("text", "")
            for step in trace
            if step.get("kind") == "think"
        ])

    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m", "mcp_server_id": "samigpt-mcp"},
    )
    result = asyncio.run(
        provider.complete("look up 1.1.1.1", mcp_client=_FakeMCP(), on_trace=on_trace)
    )

    assert result.success
    assert result.text == "1.1.1.1 is clean."
    assert any(texts and "Checking the IP." in texts[-1] and "<tool_call>" not in texts[-1] for texts in seen)
    assert any(json_body.get("stream") is True for json_body in (call.get("json") or {} for call in client.calls))


class _ResponsesStream:
    status_code = 200
    headers = {"content-type": "text/event-stream"}

    def __init__(self, lines):
        self.lines = lines

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for line in self.lines:
            yield line

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class _ResponsesClient(_RecordingClient):
    def __init__(self, lines, chat_payloads=None):
        super().__init__(passthrough_status=403, chat_payloads=chat_payloads)
        self.lines = lines

    def stream(self, method, url, headers=None, json=None):
        self.calls.append({"url": url, "json": json, "stream": True})
        return _ResponsesStream(self.lines)


def test_openwebui_responses_stream_becomes_the_reply(monkeypatch, caplog):
    caplog.set_level("INFO", logger="sami.llm.openai_compatible")
    lines = [
        "event: response.output_text.delta",
        'data: {"type":"response.output_text.delta","delta":"pon"}',
        'data: {"type":"response.output_text.delta","delta":"g"}',
        'data: {"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"pong"}]}]}}',
        "data: [DONE]",
    ]
    client = _ResponsesClient(lines)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(client))
    seen = []

    async def on_trace(trace):
        seen.append([step.get("text", "") for step in trace if step.get("kind") == "think"])

    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m"},
    )
    result = asyncio.run(provider.complete("ping", on_trace=on_trace))

    assert result.success
    assert result.text == "pong"
    assert any(texts and texts[-1] == "pon" for texts in seen)
    assert "LLM stream finished" in caplog.text
    assert "response.output_text.delta" in caplog.text
    assert "text_chars=4" in caplog.text


def test_empty_stream_retries_without_streaming(monkeypatch, caplog):
    caplog.set_level("INFO", logger="sami.llm.openai_compatible")
    client = _ResponsesClient(
        ["data: [DONE]"],
        chat_payloads=[{"choices": [{"message": {"content": "recovered"}}]}],
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncCM(client))
    provider = OpenAICompatibleProvider(
        "openwebui",
        "Open WebUI",
        {"base_url": "http://webui:8080/", "model": "m"},
    )
    result = asyncio.run(provider.complete("ping"))

    assert result.success
    assert result.text == "recovered"
    assert any(not call.get("stream") for call in client.calls)
    assert "LLM stream had no text" in caplog.text
    assert "LLM completion response" in caplog.text
    assert "text_chars=9" in caplog.text


