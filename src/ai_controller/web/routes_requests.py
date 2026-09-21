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


class BulkPayload(BaseModel):
    action: str
    request_ids: list[str] = Field(default_factory=list)
    comment: Optional[str] = None


def _payload(request: ApprovalRequest) -> Dict[str, Any]:
    data = request.to_dict()
    data["cluster"] = cluster_summary(request.cluster_id)
    from ..approval_queue.models import is_archived
    from ..approval_queue.catalog import get_action_spec, github_issue_link

    spec = get_action_spec(request.action_type)
    data["archived"] = is_archived(request)
    data["category"] = spec.category if spec else None
    data["github_issue"] = github_issue_link(request.payload)
    return data


@router.get("/catalog")
async def request_catalog():
    queue = get_queue()
    return {"success": True, "actions": queue.catalog()}


@router.get("")
async def list_requests(
    status: Optional[str] = None,
    cluster_id: Optional[str] = None,
    queue: Optional[str] = None,
):
    queue_svc = get_queue()
    try:
        items = queue_svc.list(status=status, cluster_id=cluster_id, queue=queue)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "success": True,
        "counts": queue_svc.counts(),
        "tab_counts": queue_svc.tab_counts(queue),
        "queue": queue or "all",
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


@router.post("/bulk")
async def bulk_requests(body: BulkPayload):
    if not body.request_ids:
        raise HTTPException(status_code=400, detail="request_ids is required")
    queue = get_queue()
    try:
        result = queue.bulk(action=body.action, request_ids=body.request_ids, comment=body.comment)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info(
        "Bulk %s on %s request(s): succeeded=%s skipped=%s failed=%s",
        body.action,
        len(body.request_ids),
        result.get("succeeded"),
        result.get("skipped"),
        result.get("failed"),
    )
    return {"success": True, "counts": queue.counts(), **result}


@router.post("/{request_id}/acknowledge")
async def acknowledge_request(request_id: str, body: DecisionPayload = DecisionPayload()):
    queue = get_queue()
    try:
        request = queue.acknowledge(request_id, comment=body.comment)
    except KeyError:
        raise HTTPException(status_code=404, detail="Request not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Acknowledged informational request %s", request_id)
    return {"success": True, "request": _payload(request)}


@router.post("/{request_id}/ignore")
async def ignore_request(request_id: str, body: DecisionPayload = DecisionPayload()):
    queue = get_queue()
    try:
        request = queue.ignore(request_id, comment=body.comment)
    except KeyError:
        raise HTTPException(status_code=404, detail="Request not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Ignored informational request %s", request_id)
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
