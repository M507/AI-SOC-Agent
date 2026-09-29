"""Landing dashboard: decisions, detection work, response, and spend."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...core.logging import get_logger
from ..approval_queue import get_queue
from ..session_manager import SessionType
from ..usage import cost_events, dashboard
from .overview import RANGES, build_overview

logger = get_logger("sami.web.overview")

router = APIRouter(prefix="/api/overview", tags=["overview"])


@router.get("")
async def get_overview(range: str = "30d"):
    if range not in RANGES:
        raise HTTPException(status_code=400, detail="Range must be 7d, 30d, or all")
    try:
        summary = dashboard().get("overview", {}).get(range, {})
        spend = {"cost_usd": summary.get("cost_usd"), "cost_label": summary.get("cost_label")}
    except Exception:
        logger.exception("Could not summarize spend for the dashboard")
        spend = {"cost_usd": None, "cost_label": None}
    try:
        events = cost_events().get("events") or []
    except Exception:
        logger.exception("Could not load spend events for the dashboard")
        events = None
    from .server import session_manager

    sessions = []
    autoruns = []
    if session_manager is not None:
        sessions = session_manager.list_sessions(SessionType.MANUAL)
        autoruns = session_manager.list_autoruns(enabled_only=True)
    return build_overview(
        get_queue().list(), sessions, autoruns, spend, range, spend_events=events
    )
