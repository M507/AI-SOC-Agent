"""Each LLM provider can list models and run a model test."""

from __future__ import annotations

import asyncio
import json

from src.llm.cursor_agent import CursorAgentProvider
from src.llm.registry import create_provider


class FakeResponse:
    def __init__(self, status: int, payload, content_type: str = "application/json"):
        self.status_code = status
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)
        self.headers = {"content-type": content_type}

    def json(self):
        if isinstance(self._payload, str):
            return json.loads(self._payload)
        return self._payload


class FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None):
        if url.rstrip("/").endswith("/models"):
            return FakeResponse(200, {"data": [{"id": "demo-model", "name": "Demo"}]})
        return FakeResponse(404, {"error": "not found"})

    async def post(self, url, headers=None, json=None):
        model = (json or {}).get("model") or "unknown"
        return FakeResponse(
            200,
            {"choices": [{"message": {"content": f"pong from {model}"}}]},
        )


def _run(coro):
    return asyncio.run(coro)


def test_openwebui_accepts_bare_host():
    provider = create_provider("openwebui", {"base_url": "http://10.10.10.82:8080/", "model": "gemma3:4b"})
    assert provider._base_url() == "http://10.10.10.82:8080/api/v1"
    assert provider._chat_url() == "http://10.10.10.82:8080/api/v1/chat/completions"
    assert "http://10.10.10.82:8080/api/v1/models" in provider._models_urls()
    assert "http://10.10.10.82:8080/api/models" in provider._models_urls()


def test_openai_compatible_providers_list_and_test_models(monkeypatch):
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    cases = {
        "openai": {"api_key": "sk-test", "base_url": "https://api.openai.com/v1", "model": "gpt-4o"},
        "openrouter": {"api_key": "sk-or", "base_url": "https://openrouter.ai/api/v1", "model": "openai/gpt-4o-mini"},
        "openwebui": {"api_key": "jwt", "base_url": "http://10.10.10.82:8080/", "model": "gemma3:4b"},
        "custom": {"api_key": "", "base_url": "http://127.0.0.1:11434/v1", "model": "llama3"},
    }
    for provider_id, settings in cases.items():
        provider = create_provider(provider_id, settings)
        models = _run(provider.list_models())
        assert models, f"{provider_id} returned no models"
        assert models[0]["id"] == "demo-model"

        health = _run(provider.health_check())
        assert health.ok, f"{provider_id} health failed: {health.message}"

        tested = _run(provider.test_model(settings["model"]))
        assert tested.ok, f"{provider_id} model test failed: {tested.message}"
        assert settings["model"] in tested.message or "pong" in tested.message.lower()


def test_cursor_agent_list_and_test_models():
    provider = CursorAgentProvider({})
    models = _run(provider.list_models())
    assert isinstance(models, list)
    status = _run(provider.test_model())
    assert status.message
    if provider._binary():
        assert status.ok
        assert models and models[0]["id"] == "cursor-agent"
    else:
        assert status.ok is False
        assert models == []
