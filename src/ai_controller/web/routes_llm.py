"""LLM provider settings and connectivity API."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.config_storage import get_section, update_raw_section
from ...core.logging import get_logger
from ...core.secrets import mask_mapping, merge_secrets
from ...llm.registry import create_provider, provider_catalog

logger = get_logger("sami.web.llm")

router = APIRouter(prefix="/api/llm", tags=["llm"])


class LLMSettingsUpdate(BaseModel):
    provider: str
    system_prompt: Optional[str] = None
    max_tool_iterations: Optional[int] = Field(default=None, ge=1, le=50)
    cursor_agent: Optional[Dict[str, Any]] = None
    openai: Optional[Dict[str, Any]] = None
    openrouter: Optional[Dict[str, Any]] = None
    openwebui: Optional[Dict[str, Any]] = None
    custom: Optional[Dict[str, Any]] = None


class LLMTestRequest(BaseModel):
    provider: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    model: Optional[str] = None


def _provider_from_request(request: LLMTestRequest):
    stored = get_section("llm", _default_llm_section())
    provider_id = request.provider or stored.get("provider") or "cursor_agent"
    existing_settings = stored.get(provider_id) if isinstance(stored.get(provider_id), dict) else {}
    settings = merge_secrets(request.settings or {}, existing_settings)
    if request.model:
        settings["model"] = request.model
    return provider_id, create_provider(provider_id, settings)


def _default_llm_section() -> Dict[str, Any]:
    return {
        "provider": "cursor_agent",
        "max_tool_iterations": 12,
        "cursor_agent": {},
        "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o"},
        "openrouter": {"base_url": "https://openrouter.ai/api/v1", "model": "openai/gpt-4o-mini"},
        "openwebui": {"base_url": "http://127.0.0.1:3000/api/v1", "model": ""},
        "custom": {"base_url": "http://127.0.0.1:11434/v1", "model": ""},
    }


@router.get("/providers")
async def list_providers():
    return {"success": True, "providers": provider_catalog()}


@router.get("/settings")
async def get_llm_settings():
    stored = get_section("llm", _default_llm_section())
    merged = {**_default_llm_section(), **stored}
    return {"success": True, "settings": mask_mapping(merged)}


@router.put("/settings")
async def update_llm_settings(update: LLMSettingsUpdate):
    existing = get_section("llm", _default_llm_section())
    incoming = update.model_dump(exclude_none=True)
    merged = merge_secrets(incoming, existing)
    if "provider" not in merged:
        merged["provider"] = existing.get("provider", "cursor_agent")
    update_raw_section("llm", merged)
    logger.info("LLM provider set to %s", merged.get("provider"))
    return {"success": True, "settings": mask_mapping(merged)}


@router.post("/test")
async def test_llm_provider(request: LLMTestRequest):
    try:
        _provider_id, provider = _provider_from_request(request)
        result = await provider.health_check()
        return {"success": True, **result.to_dict()}
    except Exception as e:
        logger.exception("LLM health check failed")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/models")
async def list_llm_models(request: LLMTestRequest):
    try:
        provider_id, provider = _provider_from_request(request)
        models = await provider.list_models()
        return {
            "success": True,
            "provider": provider_id,
            "models": models,
            "count": len(models),
        }
    except Exception as e:
        logger.exception("LLM model list failed")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/test-model")
async def test_llm_model(request: LLMTestRequest):
    try:
        provider_id, provider = _provider_from_request(request)
        result = await provider.test_model(request.model)
        return {"success": True, "provider": provider_id, **result.to_dict()}
    except Exception as e:
        logger.exception("LLM model test failed")
        raise HTTPException(status_code=400, detail=str(e))
