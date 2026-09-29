"""Append-only sign-in log and the merged audit feed."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from ..approval_queue.catalog import get_action_spec
from ..session_manager import Session

_LOCK = threading.Lock()
_PATH: Optional[Path] = None
_KEEP = 1000
LIMIT = 200

_SIGNIN = {
    "signed_in": "Signed in",
    "failed": "Failed sign-in",
    "signed_out": "Signed out",
}
_DECISIONS = {
    "approve": "Approved",
    "deny": "Denied",
    "acknowledge": "Reviewed",
    "ignore": "Ignored",
}


def configure_audit_log(path: Path) -> None:
    global _PATH
    _PATH = Path(path)


def audit_log_path() -> Path:
    if _PATH is None:
        return Path("data/ai_controller/audit.jsonl")
    return _PATH


def record_signin(outcome: str, username: str, ip: str) -> None:
    """Append one sign-in outcome. Never include a password or session token."""
    if outcome not in _SIGNIN:
        raise ValueError(f"Unknown sign-in outcome {outcome!r}")
    event = {
        "id": str(uuid4()),
        "at": datetime.now().isoformat(timespec="seconds"),
        "username": (username or "").strip()[:128],
        "ip": (ip or "").strip()[:64],
        "outcome": outcome,
    }
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with _LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        _trim(path)


def read_signins() -> List[Dict[str, Any]]:
    path = audit_log_path()
    if not path.is_file():
        return []
    found: List[Dict[str, Any]] = []
    with _LOCK:
        text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("outcome") in _SIGNIN:
            found.append(item)
    return found


def build_audit(
    signins: Iterable[Dict[str, Any]],
    sessions: Iterable[Session],
    requests: Iterable[Any],
    limit: int = LIMIT,
) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    for item in signins:
        outcome = item.get("outcome") or ""
        ip = (item.get("ip") or "").strip()
        label = _SIGNIN.get(outcome, "Sign-in")
        summary = f"{label} from {ip}" if ip else label
        events.append({
            "id": item.get("id") or str(uuid4()),
            "at": item.get("at") or "",
            "kind": "signin",
            "who": item.get("username") or "—",
            "summary": summary,
            "outcome": outcome,
            "ip": ip,
            "session_id": None,
            "session_name": "",
            "request_id": None,
            "title": "",
        })
    for session in sessions:
        for entry in session.entries:
            command = " ".join((entry.command or "").split())
            status = entry.status.value
            summary = command or "(empty message)"
            if status != "completed":
                summary = f"{summary} · {status}"
            events.append({
                "id": entry.id,
                "at": entry.timestamp.isoformat(timespec="seconds"),
                "kind": "chat",
                "who": session.name,
                "summary": _clip(summary, 500),
                "outcome": status,
                "ip": "",
                "session_id": session.id,
                "session_name": session.name,
                "request_id": None,
                "title": "",
            })
    for request in requests:
        decision = getattr(request, "decision", None)
        if decision is None:
            continue
        verb = _DECISIONS.get(decision.action, decision.action.replace("_", " ").title())
        spec = get_action_spec(request.action_type)
        label = spec.label if spec else request.action_type
        title = request.title or label
        events.append({
            "id": f"{request.id}:{decision.action}",
            "at": decision.at.isoformat(timespec="seconds") if decision.at else "",
            "kind": "action",
            "who": decision.actor or "analyst",
            "summary": f"{verb} {title}",
            "outcome": decision.action,
            "ip": "",
            "session_id": request.session_id,
            "session_name": "",
            "request_id": request.id,
            "title": title,
        })
    events.sort(key=lambda item: _stamp(item.get("at")), reverse=True)
    truncated = len(events) > limit
    return {
        "success": True,
        "events": events[:limit],
        "truncated": truncated,
        "limit": limit,
    }


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _stamp(value: Optional[str]) -> datetime:
    if not value:
        return datetime.min
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min
    if parsed.tzinfo is not None:
        return parsed.replace(tzinfo=None)
    return parsed


def _trim(path: Path) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [line for line in lines if line.strip()]
    if len(kept) <= _KEEP:
        return
    path.write_text("\n".join(kept[-_KEEP:]) + "\n", encoding="utf-8")
