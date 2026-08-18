import asyncio

import pytest

from src.llm import openai_compatible
from src.llm.openai_compatible import OpenAICompatibleProvider


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {"choices": [{"message": {"content": "ok"}}]}
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Client:
    """Records requests and answers the passthrough probe with a fixed status."""

    def __init__(self, passthrough_status=200):
        self.passthrough_status = passthrough_status
        self.calls = []

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "json": json})
        if "/openai/v1/" in url:
            return _Response(status_code=self.passthrough_status)
        return _Response()


@pytest.fixture(autouse=True)
def clear_route_cache():
    openai_compatible._TOOL_ROUTE_CACHE.clear()
    yield
    openai_compatible._TOOL_ROUTE_CACHE.clear()


def _provider(base_url):
    return OpenAICompatibleProvider("openwebui", "Open WebUI", {"base_url": base_url, "model": "m"})


def test_explicit_passthrough_url_is_not_downgraded():
    provider = _provider("http://webui:8080/openai/v1")

    assert provider._chat_url() == "http://webui:8080/openai/v1/chat/completions"


def test_bare_host_still_resolves_to_the_default_pipeline():
    provider = _provider("http://webui:8080")

    assert provider._chat_url() == "http://webui:8080/api/v1/chat/completions"


def test_tools_route_to_passthrough_when_it_is_enabled():
    provider = _provider("http://webui:8080")
    client = _Client(passthrough_status=200)

    url = asyncio.run(provider._tool_capable_chat_url(client, "m"))

    assert url == "http://webui:8080/openai/v1/chat/completions"


def test_tools_are_dropped_when_passthrough_is_disabled():
    provider = _provider("http://webui:8080")
    client = _Client(passthrough_status=403)

    url = asyncio.run(provider._tool_capable_chat_url(client, "m"))

    assert url is None


def test_passthrough_is_probed_only_once_per_origin():
    provider = _provider("http://webui:8080")
    client = _Client(passthrough_status=403)

    asyncio.run(provider._tool_capable_chat_url(client, "m"))
    asyncio.run(provider._tool_capable_chat_url(client, "m"))

    probes = [call for call in client.calls if "/openai/v1/" in call["url"]]
    assert len(probes) == 1
