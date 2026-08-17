"""MCP server settings, lifecycle, and health API."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.config_storage import get_section, update_raw_section
from ...core.logging import get_logger
from ...core.secrets import mask_mapping
from ...mcp.supervisor import get_supervisor

logger = get_logger("sami.web.mcp")

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


class MCPSettingsUpdate(BaseModel):
    enabled: Optional[bool] = None
    auto_start: Optional[bool] = None
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)


def _default_mcp_section() -> dict:
    return {
        "enabled": True,
        "auto_start": True,
        "host": "127.0.0.1",
        "port": 8082,
    }


@router.get("/settings")
async def get_mcp_settings():
    stored = {**_default_mcp_section(), **get_section("mcp", _default_mcp_section())}
    supervisor = get_supervisor()
    return {
        "success": True,
        "settings": mask_mapping(stored),
        "status": supervisor.status(),
    }


@router.put("/settings")
async def update_mcp_settings(update: MCPSettingsUpdate):
    existing = {**_default_mcp_section(), **get_section("mcp", _default_mcp_section())}
    incoming = update.model_dump(exclude_none=True)
    existing.update(incoming)
    update_raw_section("mcp", existing)
    return {"success": True, "settings": mask_mapping(existing), "status": get_supervisor().status()}


@router.get("/health")
async def mcp_health():
    return {"success": True, **get_supervisor().status()}


@router.post("/start")
async def start_mcp():
    settings = {**_default_mcp_section(), **get_section("mcp", _default_mcp_section())}
    try:
        status = get_supervisor().start(host=settings["host"], port=int(settings["port"]))
        return {"success": True, **status}
    except Exception as e:
        logger.exception("Failed to start MCP server")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_mcp():
    status = get_supervisor().stop()
    return {"success": True, **status}


@router.post("/restart")
async def restart_mcp():
    settings = {**_default_mcp_section(), **get_section("mcp", _default_mcp_section())}
    try:
        status = get_supervisor().restart(host=settings["host"], port=int(settings["port"]))
        return {"success": True, **status}
    except Exception as e:
        logger.exception("Failed to restart MCP server")
        raise HTTPException(status_code=500, detail=str(e))
