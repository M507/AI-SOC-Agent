"""Token usage and pricing API for the Cost view."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..usage import dashboard, load_pricing, save_pricing
from ...core.logging import get_logger

logger = get_logger("sami.web.usage")

router = APIRouter(prefix="/api/usage", tags=["usage"])


class AutoRatesUpdate(BaseModel):
    input: Optional[float] = Field(default=None, ge=0, le=1000)
    cache_write: Optional[float] = Field(default=None, ge=0, le=1000)
    cache_read: Optional[float] = Field(default=None, ge=0, le=1000)
    output: Optional[float] = Field(default=None, ge=0, le=1000)


class PricingUpdate(BaseModel):
    auto: Optional[AutoRatesUpdate] = None
    models: Optional[Dict[str, Any]] = None


@router.get("")
async def get_usage():
    try:
        return dashboard()
    except Exception as exc:
        logger.exception("Could not build usage dashboard")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/pricing")
async def get_pricing():
    try:
        return {"success": True, "pricing": load_pricing()}
    except Exception as exc:
        logger.warning("Pricing file unreadable: %s", exc)
        return {"success": False, "error": "pricing file unreadable", "detail": str(exc)}


@router.put("/pricing")
async def update_pricing(update: PricingUpdate):
    try:
        pricing = load_pricing()
    except Exception as orig:
        logger.warning("Could not load pricing file to update it: %s", orig)
        raise HTTPException(status_code=400, detail="pricing file unreadable") from orig
    models = pricing.setdefault("models", {})
    if update.models:
        for key, value in update.models.items():
            if isinstance(value, dict):
                existing = models.get(key) if isinstance(models.get(key), dict) else {}
                existing.update(value)
                models[key] = existing
    if update.auto:
        auto = models.get("auto") if isinstance(models.get("auto"), dict) else {
            "name": "Auto",
            "provider": "Cursor",
            "estimate": True,
        }
        for field_name in ("input", "cache_write", "cache_read", "output"):
            value = getattr(update.auto, field_name)
            if value is not None:
                auto[field_name] = value
        models["auto"] = auto
    saved = save_pricing(pricing)
    logger.info("Updated model pricing file")
    return {"success": True, "pricing": saved}
