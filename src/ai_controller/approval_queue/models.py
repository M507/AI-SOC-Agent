"""Persistence models for the analyst approval queue."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class RequestStatus(str, Enum):
    PENDING = "pending"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"
    AWAITING_INTEGRATION = "awaiting_integration"


@dataclass
class Decision:
    """Analyst decision recorded on a request."""

    action: str
    actor: str = "analyst"
    at: datetime = field(default_factory=datetime.now)
    comment: Optional[str] = None
    answer: Optional[str] = None
    follow_up_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["at"] = self.at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["Decision"]:
        if not data:
            return None
        payload = dict(data)
        if payload.get("at"):
            payload["at"] = datetime.fromisoformat(payload["at"])
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in payload.items() if key in allowed})


@dataclass
class FollowUpPlan:
    """What the AI wants to do after an identity question is answered."""

    id: str
    label: str
    action_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["FollowUpPlan"]:
        if not data:
            return None
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass
class ApprovalRequest:
    """An AI-suggested action waiting for (or already given) analyst approval."""

    action_type: str
    title: str
    summary: str
    id: str = field(default_factory=lambda: str(uuid4()))
    rationale: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    status: RequestStatus = RequestStatus.PENDING
    risk: str = "medium"
    cluster_id: Optional[str] = None
    session_id: Optional[str] = None
    source: str = "mcp"
    created_by: str = "ai"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    question: Optional[str] = None
    follow_ups: Dict[str, FollowUpPlan] = field(default_factory=dict)
    parent_request_id: Optional[str] = None
    child_request_ids: List[str] = field(default_factory=list)
    decision: Optional[Decision] = None
    execution_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        data["decision"] = self.decision.to_dict() if self.decision else None
        data["follow_ups"] = {
            key: plan.to_dict() if isinstance(plan, FollowUpPlan) else plan
            for key, plan in (self.follow_ups or {}).items()
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        payload = dict(data)
        payload["status"] = RequestStatus(payload.get("status") or RequestStatus.PENDING.value)
        payload["created_at"] = datetime.fromisoformat(payload["created_at"])
        payload["updated_at"] = datetime.fromisoformat(payload["updated_at"])
        payload["decision"] = Decision.from_dict(payload.get("decision"))
        raw_follow = payload.get("follow_ups") or {}
        payload["follow_ups"] = {
            key: FollowUpPlan.from_dict(value) or FollowUpPlan(id=key, label=key, action_type="")
            for key, value in raw_follow.items()
            if isinstance(value, dict)
        }
        payload.setdefault("child_request_ids", [])
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in payload.items() if key in allowed})
