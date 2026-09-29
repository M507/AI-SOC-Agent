"""Chronological audit of sign-ins, chats, and approval decisions."""

from __future__ import annotations

from fastapi import APIRouter

from ..approval_queue import get_queue
from .audit_log import build_audit, read_signins

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def get_audit():
    from .server import session_manager

    sessions = session_manager.list_sessions() if session_manager is not None else []
    return build_audit(read_signins(), sessions, get_queue().list())
