"""Factory for the configured LLM provider."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

from ..core.config_storage import get_section
from .base import LLMProvider
from .cursor_agent import CursorAgentProvider
from .openai_compatible import make_openai_provider

OpenAIProvider = make_openai_provider("openai", "OpenAI")
OpenRouterProvider = make_openai_provider("openrouter", "OpenRouter")
OpenWebUIProvider = make_openai_provider("openwebui", "Open WebUI")
CustomProvider = make_openai_provider("custom", "Custom (OpenAI-compatible)")

_PROVIDER_CLASSES: Dict[str, Type[LLMProvider]] = {
    CursorAgentProvider.provider_id: CursorAgentProvider,
    OpenAIProvider.provider_id: OpenAIProvider,
    OpenRouterProvider.provider_id: OpenRouterProvider,
    OpenWebUIProvider.provider_id: OpenWebUIProvider,
    CustomProvider.provider_id: CustomProvider,
}

PROVIDER_CATALOG: List[Dict[str, Any]] = [
    {
        "id": cls.provider_id,
        "name": cls.display_name,
        "schema": cls.settings_schema(),
    }
    for cls in _PROVIDER_CLASSES.values()
]


def provider_catalog() -> List[Dict[str, Any]]:
    return list(PROVIDER_CATALOG)


def create_provider(
    provider_id: Optional[str] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> LLMProvider:
    """
    Instantiate a provider.

    If `provider_id` is omitted, the active provider from config.json is used.
    """
    llm_cfg = get_section("llm", {"provider": "cursor_agent"})
    chosen = (provider_id or llm_cfg.get("provider") or "cursor_agent").strip()
    cls = _PROVIDER_CLASSES.get(chosen)
    if cls is None:
        raise ValueError(
            f"Unknown LLM provider {chosen!r}. "
            f"Choose one of: {', '.join(_PROVIDER_CLASSES)}"
        )
    provider_settings = dict(settings or llm_cfg.get(chosen) or {})
    if llm_cfg.get("system_prompt") and "system_prompt" not in provider_settings:
        provider_settings["system_prompt"] = llm_cfg["system_prompt"]
    if llm_cfg.get("max_tool_iterations") and "max_tool_iterations" not in provider_settings:
        provider_settings["max_tool_iterations"] = llm_cfg["max_tool_iterations"]
    return cls(provider_settings)


def get_active_provider() -> LLMProvider:
    """Convenience wrapper used by AgentExecutor."""
    return create_provider()
