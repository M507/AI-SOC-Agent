"""Finished investigation write-ups stored on completed session replies."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..session_manager import Session, SessionStatus, SessionType


def reply_text(result: Any) -> str:
    """Assistant answer text, excluding errors and in-progress replies."""
    if not isinstance(result, dict) or result.get("error") or result.get("success") is False:
        return ""
    output = result.get("output")
    if isinstance(output, str):
        return output.strip()
    if isinstance(output, dict):
        if output.get("partial"):
            return ""
        text = output.get("text")
        if isinstance(text, str):
            return text.strip()
    return ""


def list_reports(sessions: List[Session]) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for session in sessions:
        if session.session_type != SessionType.MANUAL:
            continue
        for entry in session.entries:
            if entry.status != SessionStatus.COMPLETED:
                continue
            text = reply_text(entry.result)
            if not text:
                continue
            found.append({
                "session_id": session.id,
                "session_name": session.name,
                "entry_id": entry.id,
                "command": entry.command,
                "at": entry.timestamp.isoformat(timespec="seconds"),
                "status": entry.status.value,
            })
    found.sort(key=lambda item: item["at"], reverse=True)
    return found


def find_report(sessions: List[Session], session_id: str, entry_id: str) -> Optional[Dict[str, Any]]:
    for item in list_reports(sessions):
        if item["session_id"] == session_id and item["entry_id"] == entry_id:
            session = next(row for row in sessions if row.id == session_id)
            entry = next(row for row in session.entries if row.id == entry_id)
            return {**item, "markdown": reply_text(entry.result)}
    return None
