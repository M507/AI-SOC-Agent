"""Finished investigation write-ups from completed session replies."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .reports import find_report, list_reports

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _sessions():
    from .server import session_manager

    if session_manager is None:
        return []
    return session_manager.list_sessions()


@router.get("")
async def get_reports():
    return {"success": True, "reports": list_reports(_sessions())}


@router.get("/{session_id}/{entry_id}")
async def get_report(session_id: str, entry_id: str):
    found = find_report(_sessions(), session_id, entry_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"success": True, **found}
