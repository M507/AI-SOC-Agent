"""
OpenAI-compatible chat provider.

Covers OpenAI, OpenRouter, Open WebUI, vLLM, LM Studio, Groq, and any other
API that implements `/v1/chat/completions`. MCP tools are advertised as
OpenAI function calls so investigations still use SamiGPT skills.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger
from .base import HealthStatus, LLMProvider, LLMResult

logger = get_logger("sami.llm.openai_compatible")

DEFAULT_SYSTEM_PROMPT = (
    "You are SamiGPT, an AI-powered SOC investigation assistant. "
    "You help security analysts triage alerts, investigate cases, query SIEM/EDR, "
    "and enrich indicators. Use the available tools when they help answer the "
    "request. Be concise, operational, and cite tool results rather than guessing. "
    "Do not execute irreversible response actions yourself. File them with "
    "create_approval_request (or call close_alert / isolate_endpoint / fine-tune tools, "
    "which are queued for the Requests view). Call update_alert_verdict immediately to "
    "record your working assessment; that is your verdict, not closing the alert. "
    "For suspicious logins or 'is this you?' "
    "checks, file action_type=identity_verify with a clear question and follow_ups for "
    "yes (acknowledge / close as benign) and no (escalate)."
)

# Open WebUI's /api/v1 pipeline accepts requests containing `tools` but never
# forwards them to the model, so tool calling silently does nothing. Its
# /openai/v1 passthrough does forward them, but is disabled by default
# (ENABLE_OPENAI_API_PASSTHROUGH). Probe once per origin and remember.
_TOOL_ROUTE_CACHE: Dict[str, Optional[str]] = {}

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


def mcp_tools_to_catalog(tools: List[Dict[str, Any]]) -> str:
    """Compact tool list injected into the system prompt when native FC is dropped."""
    lines = []
    for tool in tools:
        name = tool.get("name")
        if not name:
            continue
        description = re.sub(r"\s+", " ", (tool.get("description") or "").strip())
        if len(description) > 160:
            description = description[:157] + "..."
        schema = tool.get("inputSchema") or {}
        required = schema.get("required") or []
        args = ", ".join(str(item) for item in required) if required else "none required"
        lines.append(f"- {name}: {description} (args: {args})")
    return "\n".join(lines)


def _parse_tool_call_payload(raw: str) -> Optional[Dict[str, Any]]:
    """Accept JSON objects or Qwen's `name\\n{args}` tool-call bodies."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return None
    name = lines[0]
    if not re.match(r"^[\w.-]+$", name):
        return None
    arguments: Any = {}
    if len(lines) > 1:
        remainder = "\n".join(lines[1:])
        try:
            parsed = json.loads(remainder)
            arguments = parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            arguments = {"value": remainder}
    return {"name": name, "arguments": arguments}


def parse_text_tool_calls(text: str) -> List[Dict[str, Any]]:
    """Parse <tool_call>{...}</tool_call> blocks when the model cannot emit native tool_calls."""
    if not text:
        return []
    calls: List[Dict[str, Any]] = []
    start_tag = "<tool_call>"
    end_tag = "</tool_call>"
    cursor = 0
    index = 0
    while True:
        start = text.find(start_tag, cursor)
        if start < 0:
            break
        end = text.find(end_tag, start)
        if end < 0:
            break
        raw = text[start + len(start_tag) : end].strip()
        cursor = end + len(end_tag)
        payload = _parse_tool_call_payload(raw)
        if not payload:
            continue
        name = payload.get("name") or payload.get("tool")
        if not name:
            continue
        arguments = payload.get("arguments") or payload.get("args") or {}
        if not isinstance(arguments, (dict, str)):
            arguments = {}
        if isinstance(arguments, dict):
            arguments = json.dumps(arguments)
        calls.append(
            {
                "id": f"text-{index}",
                "type": "function",
                "function": {"name": str(name), "arguments": arguments},
            }
        )
        index += 1
    return calls


_PROMPT_TOOL_INSTRUCTIONS = (
    "You have SamiGPT MCP investigation tools. When a tool is required, emit one or more "
    "XML tags of this exact form and do not invent names:\n"
    '<tool_call>{"name": "tool_name", "arguments": {}}</tool_call>\n'
    "After tool results are returned, give the analyst a concise answer.\n"
    "Available tools:\n"
)


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
        if self.provider_id != "openwebui":
            return raw
        lower = raw.lower()
        # /openai/v1 is Open WebUI's passthrough and is the only route that
        # forwards `tools`, so an explicit choice of it is preserved.
        if lower.endswith("/openai/v1"):
            return raw
        if lower.endswith("/api/v1") or lower.endswith("/v1"):
            return raw
        if lower.endswith("/api"):
            return raw + "/v1"
        return f"{raw}/api/v1"

    def _origin(self) -> str:
        base = self._base_url()
        lower = base.lower()
        for suffix in ("/openai/v1", "/api/v1", "/v1", "/api"):
            if lower.endswith(suffix):
                return base[: -len(suffix)]
        return base

    def _model(self) -> str:
        return self.settings.get("model") or self._defaults().get("model") or ""

    def _api_key(self) -> str:
        return (self.settings.get("api_key") or "").strip()

    def _chat_url(self) -> str:
        base = self._base_url()
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    async def _tool_capable_chat_url(self, client: Any, model: str) -> Optional[str]:
        """
        Return a chat URL that forwards `tools`, or None if none is available.

        Only Open WebUI needs this: every other OpenAI-compatible endpoint
        honors `tools` on the configured URL.
        """
        configured = self._chat_url()
        if self.provider_id != "openwebui" or "/openai/v1/" in configured:
            return configured

        origin = self._origin()
        if origin in _TOOL_ROUTE_CACHE:
            return _TOOL_ROUTE_CACHE[origin]

        candidate = f"{origin}/openai/v1/chat/completions"
        try:
            response = await client.post(
                candidate,
                headers=self._headers(),
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                },
            )
            usable = response.status_code < 400
            detail = "" if usable else f"HTTP {response.status_code}: {response.text[:160]}"
        except Exception as e:
            usable = False
            detail = str(e)

        _TOOL_ROUTE_CACHE[origin] = candidate if usable else None
        if usable:
            logger.info("Open WebUI passthrough at %s supports tools; using it for tool calls", candidate)
        else:
            logger.warning(
                "Open WebUI at %s cannot forward native tool calls (%s). "
                "SamiGPT will advertise MCP tools in the system prompt and execute them locally.",
                origin,
                detail or "passthrough unavailable",
            )
        return _TOOL_ROUTE_CACHE[origin]

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
        mcp_tools: List[Dict[str, Any]] = []
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
            chat_url = self._chat_url()
            tools_supported: Optional[bool] = None
            tools_advertised = len(openai_tools)
            prompt_tool_fallback = False
            if openai_tools:
                tool_url = await self._tool_capable_chat_url(client, model)
                if tool_url:
                    chat_url = tool_url
                    tools_supported = True
                else:
                    # Open WebUI /api/v1 (and some Ollama proxies) accept `tools`
                    # / `tool_ids` and then drop them before the model. SamiGPT
                    # still executes tools itself, so put the catalog in the
                    # system prompt and parse <tool_call> tags from the reply.
                    catalog = mcp_tools_to_catalog(mcp_tools)
                    if catalog:
                        messages[0]["content"] = (
                            f"{messages[0]['content']}\n\n{_PROMPT_TOOL_INSTRUCTIONS}{catalog}"
                        )
                        prompt_tool_fallback = True
                        tools_supported = True
                        logger.warning(
                            "LLM endpoint does not forward native tool calls; "
                            "advertising %s MCP tools in the system prompt instead",
                            tools_advertised,
                        )
                    openai_tools = []

            for _iteration in range(max_iterations):
                if self._cancelled:
                    return LLMResult(
                        success=False,
                        text=last_text,
                        error="Cancelled",
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                        tools_advertised=tools_advertised,
                        tools_supported=tools_supported,
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
                        chat_url,
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
                        tools_advertised=tools_advertised,
                        tools_supported=tools_supported,
                    )

                last_raw = data
                choice = (data.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                last_text = message.get("content") or last_text
                native_calls = message.get("tool_calls") or []
                text_calls = [] if native_calls else parse_text_tool_calls(last_text)
                tool_calls = native_calls or text_calls
                text_tool_loop = bool(text_calls) or prompt_tool_fallback

                if not tool_calls:
                    return LLMResult(
                        success=True,
                        text=last_text or "",
                        raw=last_raw,
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                        tools_advertised=tools_advertised,
                        tools_supported=tools_supported,
                    )

                if text_tool_loop:
                    messages.append({"role": "assistant", "content": last_text or ""})
                else:
                    messages.append(message)
                if mcp_client is None:
                    return LLMResult(
                        success=True,
                        text=last_text or json.dumps(tool_calls),
                        raw=last_raw,
                        provider=self.provider_id,
                        model=model,
                        tool_calls=tool_calls_made,
                        tools_advertised=tools_advertised,
                        tools_supported=tools_supported,
                    )

                result_blocks = []
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
                    if text_tool_loop:
                        result_blocks.append(f"{name}: {result_text}")
                    else:
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.get("id") or name,
                                "content": result_text,
                            }
                        )
                if text_tool_loop:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Tool results:\n"
                                + "\n\n".join(result_blocks)
                                + "\n\nContinue. Emit another <tool_call> if needed, otherwise answer the analyst."
                            ),
                        }
                    )

            return LLMResult(
                success=True,
                text=last_text or "Reached the maximum number of tool iterations.",
                raw=last_raw,
                provider=self.provider_id,
                model=model,
                tool_calls=tool_calls_made,
                tools_advertised=tools_advertised,
                tools_supported=tools_supported,
            )

    def _models_urls(self) -> List[str]:
        base = self._base_url()
        urls = [f"{base}/models"]
        if self.provider_id == "openwebui":
            native = f"{self._origin()}/api/models"
            if native not in urls:
                urls.append(native)
        return urls

    @staticmethod
    def _parse_models(payload: Any) -> List[Dict[str, str]]:
        items: List[Any]
        if isinstance(payload, dict):
            items = payload.get("data") or payload.get("models") or []
        elif isinstance(payload, list):
            items = payload
        else:
            items = []
        models: List[Dict[str, str]] = []
        seen = set()
        for item in items:
            if isinstance(item, str):
                model_id, name = item, item
            elif isinstance(item, dict):
                model_id = item.get("id") or item.get("name") or item.get("model")
                name = item.get("name") or model_id
            else:
                continue
            if not model_id:
                continue
            model_id = str(model_id)
            if model_id in seen:
                continue
            seen.add(model_id)
            models.append({"id": model_id, "name": str(name)})
        return models

    async def list_models(self) -> List[Dict[str, str]]:
        try:
            import httpx
        except ImportError:
            return []

        headers = self._headers()
        last_error = ""
        async with httpx.AsyncClient(timeout=20.0) as client:
            for url in self._models_urls():
                try:
                    response = await client.get(url, headers=headers)
                    content_type = (response.headers.get("content-type") or "").lower()
                    if "html" in content_type or (response.text or "").lstrip().startswith("<"):
                        last_error = f"{url} returned HTML"
                        continue
                    if response.status_code == 401:
                        raise PermissionError("Authentication failed (401)")
                    if response.status_code >= 400:
                        last_error = f"HTTP {response.status_code} from {url}"
                        continue
                    models = self._parse_models(response.json())
                    if models:
                        return models
                    last_error = f"{url} returned no models"
                except PermissionError:
                    raise
                except Exception as e:
                    last_error = str(e)
        if last_error:
            logger.warning("Could not list models for %s: %s", self.provider_id, last_error)
        return []

    async def health_check(self) -> HealthStatus:
        url = self._chat_url()
        try:
            models = await self.list_models()
        except PermissionError:
            return HealthStatus(ok=False, message="Authentication failed (401)", details={"url": url})
        except Exception as e:
            return HealthStatus(ok=False, message=str(e), details={"url": url})
        if not models:
            return HealthStatus(
                ok=False,
                message="Could not list models. Check the base URL and API key.",
                details={"url": url, "models_urls": self._models_urls()},
            )
        configured = self._model()
        message = f"Reached {self.display_name} ({len(models)} models)"
        if configured:
            message += f"; selected {configured}"
        return HealthStatus(
            ok=True,
            message=message,
            details={"url": url, "model": configured, "models": [m["id"] for m in models[:50]]},
        )

    async def test_model(self, model: Optional[str] = None) -> HealthStatus:
        try:
            import httpx
        except ImportError:
            return HealthStatus(ok=False, message="httpx is not installed")

        chosen = (model or self._model() or "").strip()
        if not chosen:
            return HealthStatus(ok=False, message="No model selected. Refresh the model list and pick one.")

        url = self._chat_url()
        payload = {
            "model": chosen,
            "messages": [{"role": "user", "content": "Reply with the single word pong."}],
            "max_tokens": 16,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, headers=self._headers(), json=payload)
                if response.status_code == 401:
                    return HealthStatus(ok=False, message="Authentication failed (401)", details={"url": url, "model": chosen})
                if response.status_code >= 400:
                    return HealthStatus(
                        ok=False,
                        message=f"HTTP {response.status_code}: {response.text[:200]}",
                        details={"url": url, "model": chosen, "status": response.status_code},
                    )
                data = response.json()
                choice = (data.get("choices") or [{}])[0]
                text = ((choice.get("message") or {}).get("content") or "").strip()
                preview = text.replace("\n", " ")[:120] or "(empty response)"
                return HealthStatus(
                    ok=True,
                    message=f"{chosen} responded: {preview}",
                    details={"url": url, "model": chosen, "response": text[:500]},
                )
        except Exception as e:
            return HealthStatus(ok=False, message=str(e), details={"url": url, "model": chosen})

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
                    "type": "model",
                    "placeholder": defaults.get("model") or "Refresh to load models",
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
