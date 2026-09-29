"""Detection as Code HTTP API.

Prompts and file writes live in the detection package. This module only
maps session-authenticated requests onto those functions. The routes and
what each one writes are listed in documentation/detection-as-code.md.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ...core.elastic_clusters import client_for_id
from ...core.logging import get_logger
from ..approval_queue.models import ApprovalRequest
from ..detection.ask import ask_about_finding
from ..detection.settings import public_settings, save_settings
from ..detection.errors import DetectionError
from ..detection.findings import (
    finding_detail,
    list_findings,
    normalize_entries,
    update_finding_status,
)
from ..detection.prompts import list_ask_templates
from ..detection import review as review_service
from ..detection import rules_store
from .audit_log import record_action
from .auth import require_user

logger = get_logger("sami.web.detections")

router = APIRouter(prefix="/api/detections", tags=["detections"])


class FieldEntry(BaseModel):
    field: str
    value: str = ""


class AskBody(BaseModel):
    prompt_id: str = "ask_about"
    custom_instruction: str = ""
    entries: List[FieldEntry] = Field(default_factory=list)
    cluster_id: Optional[str] = None


class EntriesBody(BaseModel):
    entries: List[FieldEntry] = Field(default_factory=list)
    name: str = ""
    cluster_id: Optional[str] = None


class StatusBody(BaseModel):
    status: str
    entries: List[FieldEntry] = Field(default_factory=list)
    note: str = ""
    rule_id: str = ""
    cluster_id: Optional[str] = None


class SelectionBody(BaseModel):
    exceptions: List[Dict[str, Any]] = Field(default_factory=list)


class ReviseBody(BaseModel):
    feedback: str = ""
    exceptions: Optional[List[Dict[str, Any]]] = None


class RejectBody(BaseModel):
    comment: str = ""


def _http(exc: DetectionError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=str(exc))


def _client(cluster_id: Optional[str]):
    client = client_for_id(cluster_id)
    if client is None:
        raise HTTPException(status_code=409, detail="No Elastic cluster is configured.")
    return client


def _review_payload(request: ApprovalRequest) -> Dict[str, Any]:
    return review_service.review_view(request)


@router.get("/settings")
async def get_detection_settings():
    from ..approval_queue.lab_rules import DEFAULT_RULES_DIR

    return {"success": True, "settings": public_settings(DEFAULT_RULES_DIR)}


class DetectionSettingsBody(BaseModel):
    rules_dir: str = ""
    findings_hours: Optional[int] = None
    match_hours: Optional[int] = None


@router.put("/settings")
async def put_detection_settings(body: DetectionSettingsBody):
    try:
        saved = save_settings(
            rules_dir=body.rules_dir,
            findings_hours=body.findings_hours,
            match_hours=body.match_hours,
        )
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "settings": saved}


@router.get("/rules")
async def get_rules(q: str = Query(default=""), limit: int = Query(default=50, ge=1, le=100)):
    return {"success": True, **rules_store.search_catalog(q, limit=limit)}


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    try:
        return {"success": True, "rule": rules_store.rule_detail(rule_id)}
    except DetectionError as exc:
        raise _http(exc) from exc


@router.post("/rules/{rule_id}/disable")
async def disable_rule(rule_id: str, cluster_id: Optional[str] = None):
    try:
        created = review_service.create_disable(rule_id=rule_id, cluster_id=cluster_id)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(created)}


@router.get("/findings")
async def get_findings(
    q: str = Query(default=""),
    hours: Optional[int] = Query(default=None, ge=1, le=24 * 90),
    cluster_id: Optional[str] = None,
):
    try:
        alerts = list_findings(_client(cluster_id), hours=hours, query=q)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "findings": alerts, "templates": list_ask_templates()}


@router.get("/findings/{alert_id}")
async def get_finding(alert_id: str, cluster_id: Optional[str] = None):
    try:
        return {"success": True, "finding": finding_detail(_client(cluster_id), alert_id)}
    except DetectionError as exc:
        raise _http(exc) from exc


@router.post("/findings/{alert_id}/ask")
async def ask_finding(alert_id: str, body: AskBody):
    client = _client(body.cluster_id)
    entries = normalize_entries([item.model_dump() for item in body.entries])
    try:
        finding = finding_detail(client, alert_id)
        answer = await ask_about_finding(
            prompt_id=body.prompt_id,
            alert=finding,
            entries=entries,
            custom_instruction=body.custom_instruction,
        )
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, **answer}


@router.post("/findings/{alert_id}/exception")
async def exception_from_fields(alert_id: str, body: EntriesBody):
    entries = normalize_entries([item.model_dump() for item in body.entries])
    if not entries:
        raise HTTPException(status_code=400, detail="Check at least one field.")
    try:
        finding = finding_detail(_client(body.cluster_id), alert_id)
        created = review_service.create_from_fields(
            alert=finding,
            entries=entries,
            name=body.name,
            cluster_id=body.cluster_id,
        )
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(created)}


@router.post("/findings/{alert_id}/suggest")
async def suggest_finding(alert_id: str, body: EntriesBody):
    entries = normalize_entries([item.model_dump() for item in body.entries])
    if not entries:
        raise HTTPException(status_code=400, detail="Check at least one field.")
    try:
        finding = finding_detail(_client(body.cluster_id), alert_id)
        created = review_service.create_suggestion(
            alert=finding,
            entries=entries,
            cluster_id=body.cluster_id,
        )
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(created)}


@router.post("/findings/{alert_id}/status")
async def finding_status(alert_id: str, body: StatusBody, request: Request):
    user = require_user(request)
    client = _client(body.cluster_id)
    try:
        finding = finding_detail(client, alert_id)
        result = update_finding_status(
            client,
            alert_id=alert_id,
            rule_id=body.rule_id or str(finding.get("rule_id") or ""),
            entries=[item.model_dump() for item in body.entries],
            status=body.status,
            note=body.note,
        )
    except DetectionError as exc:
        raise _http(exc) from exc
    note_bit = "with a note" if result.get("note") else "without a note"
    record_action(
        str(user.get("username") or "analyst"),
        f"{body.status} {len(result.get('updated') or [])} alert(s) {note_bit} for {finding.get('rule_name') or alert_id}",
    )
    return {"success": True, **result}


@router.get("/reviews")
async def get_reviews():
    return {
        "success": True,
        "reviews": [_review_payload(item) for item in review_service.list_reviews()],
        "folder": rules_store.folder_status(),
    }


@router.get("/reviews/{request_id}")
async def get_review(request_id: str):
    try:
        return {"success": True, "review": _review_payload(review_service.get_review(request_id))}
    except DetectionError as exc:
        raise _http(exc) from exc


@router.post("/reviews/{request_id}/draft")
async def draft_review(request_id: str):
    try:
        updated = await review_service.draft(request_id)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(updated)}


@router.post("/reviews/{request_id}/revise")
async def revise_review(request_id: str, body: ReviseBody):
    try:
        updated = await review_service.revise(request_id, body.feedback, body.exceptions)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(updated)}


@router.post("/reviews/{request_id}/selection")
async def select_review(request_id: str, body: SelectionBody):
    try:
        updated = review_service.update_selection(request_id, body.exceptions)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(updated)}


@router.post("/reviews/{request_id}/implement")
async def implement_review(request_id: str):
    try:
        updated = review_service.implement(request_id)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(updated)}


@router.post("/reviews/{request_id}/reject")
async def reject_review(request_id: str, body: RejectBody = RejectBody()):
    try:
        updated = review_service.reject(request_id, body.comment)
    except DetectionError as exc:
        raise _http(exc) from exc
    return {"success": True, "review": _review_payload(updated)}
