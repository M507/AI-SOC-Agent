"""HTTP API for the setup wizard. The page and the onboarding test share it."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...core.logging import get_logger
from ...core.secrets import merge_secrets
from ...llm.registry import create_provider
from .auth import get_auth
from .setup_wizard import OPENWEBUI_MCP_ID, apply_step, build_schema, status_payload

logger = get_logger("sami.web.setup")

router = APIRouter(prefix="/api/setup", tags=["setup"])


class StepBody(BaseModel):
    action: str = "save"
    values: Dict[str, Any] = Field(default_factory=dict)


class ModelRefreshBody(BaseModel):
    provider: str = "openwebui"
    settings: Dict[str, Any] = Field(default_factory=dict)


class ConnectBody(BaseModel):
    public_url: str = ""


@router.get("/status")
async def setup_status():
    return status_payload()


@router.get("/schema")
async def setup_schema():
    return build_schema()


@router.post("/steps/{step_id}")
async def save_step(step_id: str, body: StepBody):
    result = apply_step(step_id, body.action, body.values)
    if not result.get("success"):
        return JSONResponse(status_code=400, content=result)
    response = JSONResponse(content=result)
    if result.get("session"):
        auth = get_auth()
        token = auth.create_session(result.get("username") or auth.config.username)
        auth.set_cookie(response, token)
    return response


@router.post("/complete")
async def complete_setup():
    result = apply_step("review", "save", {})
    if not result.get("success"):
        return JSONResponse(status_code=400, content=result)
    result["next_step"] = "done"
    return result


@router.post("/llm/models")
async def refresh_models(body: ModelRefreshBody):
    """List models for an unsaved provider key. Does not write config."""
    from ...core.config_storage import get_section

    stored = get_section("llm", {})
    existing = stored.get(body.provider) if isinstance(stored.get(body.provider), dict) else {}
    settings = merge_secrets(body.settings or {}, existing)
    try:
        provider = create_provider(body.provider, settings)
        models = await provider.list_models()
    except Exception as exc:
        logger.info("Setup model refresh failed for provider %s", body.provider)
        return JSONResponse(status_code=400, content={"success": False, "detail": str(exc)})
    ids = []
    for item in models or []:
        if isinstance(item, dict) and item.get("id"):
            ids.append(str(item["id"]))
        elif isinstance(item, str):
            ids.append(item)
    if body.provider == "openwebui" and "auto" not in ids:
        ids.insert(0, "auto")
    return {"success": True, "provider": body.provider, "models": ids}


@router.post("/openwebui/connect")
async def register_openwebui(body: ConnectBody):
    """Optional. The onboarding script does not call this."""
    from ..openwebui_mcp import connect

    public_url = (body.public_url or "").strip()
    if len(public_url) < 8:
        return JSONResponse(status_code=400, content={"success": False, "detail": "Public MCP URL is required."})
    try:
        result = await connect(public_url)
    except Exception as exc:
        logger.info("Setup Open WebUI registration failed")
        return JSONResponse(status_code=400, content={"success": False, "detail": str(exc)})
    return {"success": True, "mcp_server_id": OPENWEBUI_MCP_ID, **result}
