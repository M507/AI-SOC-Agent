"""NetBox settings API for the web UI."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.config import NetBoxConfig, SamiConfig
from ...core.config_storage import get_section, update_raw_section
from ...core.logging import get_logger
from ...core.secrets import mask_mapping, merge_secrets
from ...integrations.netbox import NetBoxAPIClient
from ...mcp.supervisor import get_supervisor

logger = get_logger("sami.web.netbox")

router = APIRouter(prefix="/api/netbox", tags=["netbox"])


class NetBoxSettingsUpdate(BaseModel):
    base_url: str = Field(min_length=1)
    api_token: Optional[str] = None
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    verify_ssl: bool = True


def _default_netbox() -> Dict[str, Any]:
    return {
        "base_url": "",
        "api_token": "",
        "timeout_seconds": 30,
        "verify_ssl": True,
    }


def _reload_mcp() -> None:
    try:
        supervisor = get_supervisor()
        if supervisor.is_running:
            supervisor.restart()
            logger.info("Restarted MCP server after NetBox settings change")
    except Exception as e:
        logger.warning("MCP reload after NetBox settings change failed: %s", e)


@router.get("/settings")
async def get_netbox_settings():
    stored = {**_default_netbox(), **(get_section("netbox", {}) or {})}
    return {"success": True, "settings": mask_mapping(stored)}


@router.put("/settings")
async def update_netbox_settings(update: NetBoxSettingsUpdate):
    existing = get_section("netbox", _default_netbox()) or {}
    incoming = update.model_dump(exclude_none=False)
    # Blank token in the form means "keep existing"
    if not (incoming.get("api_token") or "").strip():
        incoming["api_token"] = existing.get("api_token") or ""
    merged = merge_secrets(incoming, existing)
    if not merged.get("base_url"):
        raise HTTPException(status_code=400, detail="base_url is required")
    if not merged.get("api_token"):
        raise HTTPException(status_code=400, detail="api_token is required")
    update_raw_section("netbox", merged)
    _reload_mcp()
    logger.info("NetBox settings saved url=%s", merged.get("base_url"))
    return {"success": True, "settings": mask_mapping(merged)}


@router.post("/test")
async def test_netbox_settings(update: Optional[NetBoxSettingsUpdate] = None):
    existing = get_section("netbox", _default_netbox()) or {}
    if update is not None:
        incoming = update.model_dump(exclude_none=False)
        if not (incoming.get("api_token") or "").strip():
            incoming["api_token"] = existing.get("api_token") or ""
        settings = merge_secrets(incoming, existing)
    else:
        settings = existing

    if not settings.get("base_url") or not settings.get("api_token"):
        raise HTTPException(status_code=400, detail="Configure NetBox URL and API token first")

    client = NetBoxAPIClient.from_config(
        SamiConfig(
            netbox=NetBoxConfig(
                base_url=str(settings["base_url"]),
                api_token=str(settings["api_token"]),
                timeout_seconds=int(settings.get("timeout_seconds") or 30),
                verify_ssl=bool(settings.get("verify_ssl", True)),
            )
        )
    )
    ok = await asyncio.to_thread(client.ping)
    if not ok:
        return {
            "success": False,
            "ok": False,
            "level": "error",
            "message": "NetBox API status check failed.",
        }
    return {
        "success": True,
        "ok": True,
        "level": "success",
        "message": f"NetBox API is reachable at {settings.get('base_url')}.",
    }
