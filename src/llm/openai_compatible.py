"""
OpenAI-compatible chat provider.

Covers OpenAI, OpenRouter, Open WebUI, vLLM, LM Studio, Groq, and any other
API that implements `/v1/chat/completions`. MCP tools are advertised as
OpenAI function calls so investigations still use SamiGPT skills.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger
from .base import HealthStatus, LLMProvider, LLMResult

logger = get_logger("sami.llm.openai_compatible")

DEFAULT_SYSTEM_PROMPT = (
    "You are SamiGPT, an AI-powered SOC investigation assistant. "
    "You help security analysts triage alerts, investigate cases, query SIEM/EDR, "
    "and enrich indicators. Use the available tools when they help answer the "
    "request. Be concise, operational, and cite tool results rather than guessing."
)

_DEFAULTS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "openai/gpt-4o-mini",
    },
    "openwebui": {
        "base_url": "http://127.0.0.1:3000/api/v1",
        "model": "",
    },
    "custom": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "",
    },
}


def mcp_tools_to_openai(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert MCP tool definitions to OpenAI function-calling tools."""
    converted = []
    for tool in tools:
        name = tool.get("name")
        if not name:
            continue
        parameters = tool.get("inputSchema") or {"type": "object", "properties": {}}
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.get("description") or name,
                    "parameters": parameters,
                },
            }
        )
    return converted


class OpenAICompatibleProvider(LLMProvider):
    """Chat Completions client with optional MCP tool-calling loop."""

    def __init__(
        self,
        provider_id: str,
        display_name: str,
        settings: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(settings)
        self.provider_id = provider_id
        self.display_name = display_name
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _defaults(self) -> Dict[str, str]:
        return _DEFAULTS.get(self.provider_id, _DEFAULTS["custom"])

    def _base_url(self) -> str:
        raw = (self.settings.get("base_url") or self._defaults()["base_url"]).rstrip("/")
        return raw

    def _model(self) -> str:
        return self.settings.get("model") or self._defaults().get("model") or ""

    def _api_key(self) -> str:
        return (self.settings.get("api_key") or "").strip()

    def _chat_url(self) -> str:
        base = self._base_url()
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        api_key = self._api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if self.provider_id == "openrouter":
            headers["HTTP-Referer"] = self.settings.get("site_url") or "http://localhost"
            headers["X-Title"] = self.settings.get("app_name") or "SamiGPT"
        extra = self.settings.get("extra_headers")
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        return headers

    async def complete(self, prompt: str, **kwargs: Any) -> LLMResult:
        self._cancelled = False
        model = self._model()
        if not model:
            return LLMResult(
                success=False,
                text="",
                error="No model configured. Set a model in Settings.",
                provider=self.provider_id,
            )

        system_prompt = kwargs.get("system_prompt") or self.settings.get("system_prompt") or DEFAULT_SYSTEM_PROMPT
        max_iterations = int(kwargs.get("max_tool_iterations") or self.settings.get("max_tool_iterations") or 12)
        mcp_client = kwargs.get("mcp_client")

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        openai_tools: List[Dict[str, Any]] = []
        if mcp_client is not None:
            try:
                mcp_tools = await mcp_client.list_tools()
                openai_tools = mcp_tools_to_openai(mcp_tools)
            except Exception as e:
                logger.warning("Could not load MCP tools for %s: %s", self.provider_id, e)

        tool_calls_made = 0
        last_text = ""
        last_raw: Any = None

        try:
            import httpx
        except ImportError:
            return LLMResult(
                success=False,
                text="",
                error="httpx is required for OpenAI-compatible providers. pip install httpx",
                provider=self.provider_id,
                model=model,
            )

        timeout = float(self.settings.get("timeout_seconds") or 120)
        async with httpx.AsyncClient(timeout=timeout) as client:
            for _iteration in range(max_iterations):
                if self._cancelled:
                    return LLMResult(
                        success=False,
                        text=last_text,
                        error="Cancelled",
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                    )

                payload: Dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                }
                if openai_tools:
                    payload["tools"] = openai_tools
                    payload["tool_choice"] = "auto"

                try:
                    response = await client.post(
                        self._chat_url(),
                        headers=self._headers(),
                        json=payload,
                    )
                    response.raise_for_status()
                    data = response.json()
                except Exception as e:
                    logger.exception("LLM request failed for %s", self.provider_id)
                    return LLMResult(
                        success=False,
                        text=last_text,
                        error=str(e),
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                    )

                last_raw = data
                choice = (data.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                last_text = message.get("content") or last_text
                tool_calls = message.get("tool_calls") or []

                if not tool_calls:
                    return LLMResult(
                        success=True,
                        text=last_text or "",
                        raw=last_raw,
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                    )

                messages.append(message)
                if mcp_client is None:
                    return LLMResult(
                        success=True,
                        text=last_text or json.dumps(tool_calls),
                        raw=last_raw,
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                    )

                for call in tool_calls:
                    fn = call.get("function") or {}
                    name = fn.get("name") or ""
                    raw_args = fn.get("arguments") or "{}"
                    try:
                        arguments = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                    except json.JSONDecodeError:
                        arguments = {}
                    result_text = await mcp_client.call_tool(name, arguments)
                    tool_calls_made += 1
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.get("id") or name,
                            "content": result_text,
                        }
                    )

            return LLMResult(
                success=True,
                text=last_text or "Reached the maximum number of tool iterations.",
                raw=last_raw,
                provider=self.provider_id,
                model=model,
                tool_calls=tool_calls_made,
            )

    async def health_check(self) -> HealthStatus:
        try:
            import httpx
        except ImportError:
            return HealthStatus(ok=False, message="httpx is not installed")

        url = self._chat_url()
        model = self._model()
        if not model:
            return HealthStatus(ok=False, message="No model configured", details={"url": url})

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 8,
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(url, headers=self._headers(), json=payload)
                if response.status_code == 401:
                    return HealthStatus(ok=False, message="Authentication failed (401)", details={"url": url})
                if response.status_code >= 400:
                    return HealthStatus(
                        ok=False,
                        message=f"HTTP {response.status_code}: {response.text[:200]}",
                        details={"url": url, "status": response.status_code},
                    )
                return HealthStatus(
                    ok=True,
                    message=f"Reached {self.display_name} ({model})",
                    details={"url": url, "model": model},
                )
        except Exception as e:
            return HealthStatus(ok=False, message=str(e), details={"url": url})

    @classmethod
    def settings_schema(cls) -> Dict[str, Any]:
        return {
            "fields": [
                {"key": "api_key", "label": "API key", "type": "password", "placeholder": "sk-..."},
                {"key": "base_url", "label": "Base URL", "type": "text", "placeholder": "https://api.openai.com/v1"},
                {"key": "model", "label": "Model", "type": "text", "placeholder": "gpt-4o"},
            ]
        }


def make_openai_provider(provider_id: str, display_name: str):
    """Factory used by the registry so each catalog entry is a real class."""

    class _Bound(OpenAICompatibleProvider):
        def __init__(self, settings: Optional[Dict[str, Any]] = None) -> None:
            super().__init__(provider_id, display_name, settings)

        @classmethod
        def settings_schema(cls) -> Dict[str, Any]:
            defaults = _DEFAULTS.get(provider_id, _DEFAULTS["custom"])
            fields = [
                {
                    "key": "api_key",
                    "label": "API key",
                    "type": "password",
                    "placeholder": "Leave blank if the endpoint does not require a key",
                },
                {
                    "key": "base_url",
                    "label": "Base URL",
                    "type": "text",
                    "placeholder": defaults["base_url"],
                },
                {
                    "key": "model",
                    "label": "Model",
                    "type": "text",
                    "placeholder": defaults.get("model") or "model-id",
                },
            ]
            if provider_id == "openrouter":
                fields.append(
                    {
                        "key": "site_url",
                        "label": "Site URL (OpenRouter referer)",
                        "type": "text",
                        "placeholder": "http://localhost",
                    }
                )
            if provider_id == "custom":
                fields.append(
                    {
                        "key": "timeout_seconds",
                        "label": "Timeout (seconds)",
                        "type": "number",
                        "placeholder": "120",
                    }
                )
            return {"fields": fields}

    _Bound.provider_id = provider_id
    _Bound.display_name = display_name
    _Bound.__name__ = f"{display_name.replace(' ', '')}Provider"
    return _Bound
