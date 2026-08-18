"""Analyst approval-queue API (SamiGPT Requests view)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.elastic_clusters import cluster_summary
from ...core.logging import get_logger
from ..approval_queue import get_queue
from ..approval_queue.models import ApprovalRequest

logger = get_logger("sami.web.requests")

router = APIRouter(prefix="/api/requests", tags=["requests"])


class CreateRequestPayload(BaseModel):
    action_type: str
    title: str
    summary: str = ""
    rationale: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)
    cluster_id: Optional[str] = None
    session_id: Optional[str] = None
    question: Optional[str] = None
    follow_ups: Optional[Dict[str, Any]] = None


class DecisionPayload(BaseModel):
    comment: Optional[str] = None


class AnswerPayload(BaseModel):
    answer: str
    comment: Optional[str] = None


def _payload(request: ApprovalRequest) -> Dict[str, Any]:
    data = request.to_dict()
    data["cluster"] = cluster_summary(request.cluster_id)
    return data


@router.get("/catalog")
async def request_catalog():
    queue = get_queue()
    return {"success": True, "actions": queue.catalog()}


@router.get("")
async def list_requests(status: Optional[str] = None, cluster_id: Optional[str] = None):
    queue = get_queue()
    try:
        items = queue.list(status=status, cluster_id=cluster_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "success": True,
        "counts": queue.counts(),
        "requests": [_payload(item) for item in items],
    }


@router.post("")
async def create_request(body: CreateRequestPayload):
    queue = get_queue()
    try:
        request = queue.create(
            action_type=body.action_type,
            title=body.title,
            summary=body.summary,
            payload=body.payload,
            rationale=body.rationale,
            cluster_id=body.cluster_id,
            session_id=body.session_id,
            question=body.question,
            follow_ups=body.follow_ups,
            source="api",
            created_by="analyst",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Created approval request %s (%s)", request.id, request.action_type)
    return {"success": True, "request": _payload(request)}


@router.get("/{request_id}")
async def get_request(request_id: str):
    request = get_queue().get(request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return {"success": True, "request": _payload(request)}


@router.post("/{request_id}/approve")
async def approve_request(request_id: str, body: DecisionPayload = DecisionPayload()):
    queue = get_queue()
    try:
        request = queue.approve(request_id, comment=body.comment)
    except KeyError:
        raise HTTPException(status_code=404, detail="Request not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Approved request %s -> %s", request_id, request.status.value)
    return {"success": True, "request": _payload(request)}


@router.post("/{request_id}/deny")
async def deny_request(request_id: str, body: DecisionPayload = DecisionPayload()):
    queue = get_queue()
    try:
        request = queue.deny(request_id, comment=body.comment)
    except KeyError:
        raise HTTPException(status_code=404, detail="Request not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Denied request %s", request_id)
    return {"success": True, "request": _payload(request)}


@router.post("/{request_id}/answer")
async def answer_request(request_id: str, body: AnswerPayload):
    queue = get_queue()
    try:
        request = queue.answer(request_id, answer=body.answer, comment=body.comment)
    except KeyError:
        raise HTTPException(status_code=404, detail="Request not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Answered request %s with %s -> %s", request_id, body.answer, request.status.value)
    return {"success": True, "request": _payload(request)}
