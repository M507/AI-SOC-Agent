"""Review lifecycle stored on a fine-tune note. The model runs only on Draft or Revise.

The note stays informational. Done or Ignore on the Requests tab does
not write the file. Implement is the only writer, and it does not close
the alert. Field exceptions and disables start at stage drafted with
nothing written. Suggest with AI starts at proposed so the first model
call is the explicit Draft button. See documentation/detection-as-code.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..approval_queue import get_queue
from ..approval_queue.models import ApprovalRequest, RequestStatus, is_archived
from . import rules_store
from .diff import unified_diff
from .drafting import complete_draft
from .errors import DetectionError
from .apply import write_disabled, write_exceptions
from .validation import validate_checked


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _dac(request: ApprovalRequest) -> Dict[str, Any]:
    payload = request.payload or {}
    dac = payload.get("dac")
    return dict(dac) if isinstance(dac, dict) else {}


def _save(request: ApprovalRequest, dac: Dict[str, Any]) -> ApprovalRequest:
    payload = dict(request.payload or {})
    payload["dac"] = dac
    request.payload = payload
    request.updated_at = datetime.now()
    return get_queue().store.put(request)


def current_revision(dac: Dict[str, Any]) -> Dict[str, Any]:
    revisions = dac.get("revisions") if isinstance(dac.get("revisions"), list) else []
    if not revisions:
        return {}
    index = int(dac.get("current_revision") or 0)
    index = max(0, min(index, len(revisions) - 1))
    item = revisions[index]
    return dict(item) if isinstance(item, dict) else {}


def _open_fine_tune(alert_id: str, rule_id: str) -> Optional[ApprovalRequest]:
    for item in get_queue().list(queue="detection"):
        if item.action_type != "fine_tune" or is_archived(item):
            continue
        dac = _dac(item)
        if dac.get("stage") in {"implemented", "rejected"}:
            continue
        payload = item.payload or {}
        same_alert = not alert_id or str(payload.get("alert_id") or "") == alert_id
        same_rule = not rule_id or str(payload.get("rule_id") or dac.get("rule_id") or "") == rule_id
        if same_alert and same_rule:
            return item
    return None


def _seed_dac(
    *,
    kind: str,
    stage: str,
    path,
    digest: str,
    rule_id: str,
    evidence_fields: List[str],
    revision: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "stage": stage,
        "kind": kind,
        "file": str(path),
        "file_sha256": digest,
        "rule_id": rule_id,
        "evidence_fields": evidence_fields,
        "revisions": [revision] if revision else [],
        "current_revision": 0,
    }


def _field_built_revision(entries: List[Dict[str, str]], name: Optional[str]) -> Dict[str, Any]:
    # selected starts false so opening Review does not write the file.
    # Implement stays blocked until the analyst checks the card.
    label = (name or "").strip() or " / ".join(f"{entry['field']}={entry['value']}" for entry in entries[:3])
    return {
        "at": _now(),
        "feedback": "",
        "rationale": "Built from the fields checked on the finding.",
        "safe_to_except": True,
        "notes": "",
        "exceptions": [
            {
                "name": label[:120],
                "confidence": "high",
                "entries": entries,
                "selected": False,
                "allow_wildcard": False,
            }
        ],
    }


def ensure_rule_snapshot(rule_id: str, rule_name: str = "") -> tuple:
    return rules_store.load_rule_file(rule_id=rule_id or None, rule_name=rule_name or None)


def create_from_fields(
    *,
    alert: Dict[str, Any],
    entries: List[Dict[str, str]],
    name: Optional[str] = None,
    cluster_id: Optional[str] = None,
) -> ApprovalRequest:
    rule_id = str(alert.get("rule_id") or "")
    rule_name = str(alert.get("rule_name") or alert.get("title") or "")
    existing = _open_fine_tune(str(alert.get("id") or ""), rule_id)
    path, data, digest = ensure_rule_snapshot(rule_id, rule_name)
    evidence = sorted({entry["field"] for entry in entries})
    revision = _field_built_revision(entries, name)
    resolved_id = str((data.get("_dac") or {}).get("rule_id") or (data.get("rule") or {}).get("rule_id") or rule_id)
    excerpt_name = str((data.get("rule") or {}).get("name") or rule_name)
    dac = _seed_dac(
        kind="exceptions",
        stage="drafted",
        path=path,
        digest=digest,
        rule_id=resolved_id,
        evidence_fields=evidence,
        revision=revision,
    )
    title = f"Exception for {excerpt_name or resolved_id}"
    summary = revision["exceptions"][0]["name"]
    if existing is not None:
        existing_dac = _dac(existing)
        existing_dac.update({
            "stage": "drafted",
            "kind": "exceptions",
            "file": str(path),
            "file_sha256": digest,
            "rule_id": resolved_id,
            "evidence_fields": evidence,
        })
        revisions = list(existing_dac.get("revisions") or [])
        revisions.append(revision)
        existing_dac["revisions"] = revisions
        existing_dac["current_revision"] = len(revisions) - 1
        return _save(existing, existing_dac)
    request = get_queue().create(
        action_type="fine_tune",
        title=title,
        summary=summary,
        rationale=revision["rationale"],
        payload={
            "title": title,
            "description": summary,
            "rule_id": resolved_id,
            "rule_name": excerpt_name,
            "alert_id": alert.get("id") or "",
            "dac": dac,
        },
        cluster_id=cluster_id,
        source="api",
        created_by="analyst",
    )
    # create() enriches the payload; put the draft back in case enrichment dropped it.
    return _save(request, dac)


def create_suggestion(
    *,
    alert: Dict[str, Any],
    entries: List[Dict[str, str]],
    cluster_id: Optional[str] = None,
) -> ApprovalRequest:
    rule_id = str(alert.get("rule_id") or "")
    rule_name = str(alert.get("rule_name") or alert.get("title") or "")
    existing = _open_fine_tune(str(alert.get("id") or ""), rule_id)
    if existing is not None and _dac(existing).get("stage") == "proposed":
        return existing
    path, data, digest = ensure_rule_snapshot(rule_id, rule_name)
    resolved_id = str((data.get("_dac") or {}).get("rule_id") or rule_id)
    excerpt_name = str((data.get("rule") or {}).get("name") or rule_name)
    dac = _seed_dac(
        kind="exceptions",
        stage="proposed",
        path=path,
        digest=digest,
        rule_id=resolved_id,
        evidence_fields=sorted({entry["field"] for entry in entries}),
    )
    dac["selected_alerts"] = [{
        "id": alert.get("id"),
        "rule_id": resolved_id,
        "rule_name": excerpt_name,
        "selected_fields": entries,
    }]
    title = f"Fine-tune {excerpt_name or resolved_id}"
    summary = "Draft exceptions after review. The model has not run yet."
    request = get_queue().create(
        action_type="fine_tune",
        title=title,
        summary=summary,
        rationale=summary,
        payload={
            "title": title,
            "description": summary,
            "rule_id": resolved_id,
            "rule_name": excerpt_name,
            "alert_id": alert.get("id") or "",
            "dac": dac,
        },
        cluster_id=cluster_id,
        source="api",
        created_by="analyst",
    )
    return _save(request, dac)


def create_disable(*, rule_id: str, cluster_id: Optional[str] = None) -> ApprovalRequest:
    path, data, digest = ensure_rule_snapshot(rule_id, "")
    resolved_id = str((data.get("_dac") or {}).get("rule_id") or rule_id)
    name = str((data.get("rule") or {}).get("name") or resolved_id)
    dac = _seed_dac(
        kind="disable",
        stage="drafted",
        path=path,
        digest=digest,
        rule_id=resolved_id,
        evidence_fields=[],
        revision={
            "at": _now(),
            "feedback": "",
            "rationale": "Disable this rule in the configured folder.",
            "safe_to_except": False,
            "notes": "",
            "exceptions": [],
        },
    )
    title = f"Disable {name}"
    summary = "Disable the rule file after review. Nothing is written until Implement."
    request = get_queue().create(
        action_type="fine_tune",
        title=title,
        summary=summary,
        rationale=summary,
        payload={
            "title": title,
            "description": summary,
            "rule_id": resolved_id,
            "rule_name": name,
            "dac": dac,
        },
        cluster_id=cluster_id,
        source="api",
        created_by="analyst",
    )
    return _save(request, dac)


def list_reviews() -> List[ApprovalRequest]:
    items = []
    for item in get_queue().list(queue="detection"):
        if item.action_type != "fine_tune":
            continue
        if not _dac(item):
            continue
        items.append(item)
    return items


def get_review(request_id: str) -> ApprovalRequest:
    request = get_queue().get(request_id)
    if request is None or request.action_type != "fine_tune":
        raise DetectionError("Review not found.", status_code=404)
    return request


def _diff_for(request: ApprovalRequest, dac: Dict[str, Any]) -> str:
    path, data, _digest = rules_store.load_rule_file(rule_id=dac.get("rule_id") or (request.payload or {}).get("rule_id"))
    before = rules_store.document_text(data)
    if dac.get("kind") == "disable":
        after = rules_store.document_text(rules_store.render_disabled(data))
    else:
        revision = current_revision(dac)
        cards = revision.get("exceptions") or []
        checked = [card for card in cards if isinstance(card, dict) and card.get("selected") is not False]
        additions = []
        from .apply import exception_item

        rule_id = str(dac.get("rule_id") or "")
        additions = [exception_item(rule_id, card) for card in checked]
        after = rules_store.document_text(rules_store.render_with_exceptions(data, additions))
    return unified_diff(before, after, path.name)


def review_view(request: ApprovalRequest) -> Dict[str, Any]:
    dac = _dac(request)
    revision = current_revision(dac)
    overview = {}
    diff = ""
    warnings: List[str] = []
    error = ""
    try:
        detail = rules_store.rule_detail(str(dac.get("rule_id") or (request.payload or {}).get("rule_id") or ""))
        overview = {
            "rule_id": detail.get("rule_id"),
            "name": detail.get("name"),
            "severity": detail.get("severity"),
            "language": detail.get("language"),
            "query": detail.get("query"),
            "exception_count": detail.get("exception_count"),
            "file": detail.get("file"),
            "status": detail.get("status"),
        }
        diff = _diff_for(request, dac)
        if dac.get("kind") != "disable" and revision.get("exceptions"):
            # Preview only. "Nothing checked yet" is a hint in the UI, not a failed load.
            warnings = validate_checked(
                revision.get("exceptions") or [],
                existing_items=detail.get("exception_items") or [],
                evidence_fields=list(dac.get("evidence_fields") or []),
                enforce_selection=False,
            )
    except DetectionError as exc:
        error = str(exc)
    payload = request.payload or {}
    return {
        "id": request.id,
        "title": request.title,
        "summary": request.summary,
        "status": request.status.value,
        "archived": is_archived(request),
        "stage": dac.get("stage") or "proposed",
        "kind": dac.get("kind") or "exceptions",
        "alert_id": payload.get("alert_id") or "",
        "rule_id": dac.get("rule_id") or payload.get("rule_id") or "",
        "rule_name": payload.get("rule_name") or "",
        "rationale": revision.get("rationale") or request.rationale or "",
        "safe_to_except": revision.get("safe_to_except"),
        "notes": revision.get("notes") or "",
        "exceptions": revision.get("exceptions") or [],
        "revision_count": len(dac.get("revisions") or []),
        "overview": overview,
        "diff": diff,
        "warnings": warnings,
        "error": error,
    }


def update_selection(request_id: str, exceptions: List[Dict[str, Any]]) -> ApprovalRequest:
    request = get_review(request_id)
    dac = _dac(request)
    if dac.get("stage") not in {"proposed", "drafted"}:
        raise DetectionError("This review can no longer be edited.")
    revisions = list(dac.get("revisions") or [])
    if not revisions:
        raise DetectionError("There is nothing to select yet. Draft the exceptions first.")
    index = int(dac.get("current_revision") or 0)
    current = dict(revisions[index])
    by_name = []
    posted = exceptions or []
    existing = current.get("exceptions") or []
    if len(posted) != len(existing):
        raise DetectionError("Send every condition when updating the checks.")
    for item, posted_item in zip(existing, posted):
        updated = dict(item)
        updated["selected"] = bool(posted_item.get("selected", True))
        updated["allow_wildcard"] = bool(posted_item.get("allow_wildcard", False))
        by_name.append(updated)
    current["exceptions"] = by_name
    revisions[index] = current
    dac["revisions"] = revisions
    return _save(request, dac)


def _alerts_for_draft(request: ApprovalRequest, dac: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = request.payload or {}
    selected = dac.get("selected_alerts")
    if isinstance(selected, list) and selected:
        return selected
    return [{
        "id": payload.get("alert_id"),
        "rule_id": dac.get("rule_id") or payload.get("rule_id"),
        "rule_name": payload.get("rule_name"),
        "selected_fields": [{"field": field, "value": ""} for field in (dac.get("evidence_fields") or [])],
    }]


async def draft(request_id: str) -> ApprovalRequest:
    request = get_review(request_id)
    if is_archived(request) or request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Draft is only available while the note is open.")
    dac = _dac(request)
    if dac.get("kind") == "disable":
        raise DetectionError("Disable reviews do not call the model.")
    if dac.get("stage") != "proposed":
        raise DetectionError("Draft runs only before the first suggestion.")
    path, data, digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    suggestions = await complete_draft(
        rule_file=data,
        alerts=_alerts_for_draft(request, dac),
        request_id=request.id,
        command="detection draft",
    )
    revision = {"at": _now(), "feedback": "", **suggestions}
    dac["stage"] = "drafted"
    dac["file"] = str(path)
    dac["file_sha256"] = digest
    dac["revisions"] = [revision]
    dac["current_revision"] = 0
    return _save(request, dac)


async def revise(request_id: str, feedback: str, exceptions: Optional[List[Dict[str, Any]]] = None) -> ApprovalRequest:
    text = (feedback or "").strip()
    if not text:
        raise DetectionError("Tell the model what to change.")
    if exceptions is not None:
        update_selection(request_id, exceptions)
    request = get_review(request_id)
    dac = _dac(request)
    if dac.get("kind") == "disable":
        raise DetectionError("Disable reviews do not call the model.")
    if dac.get("stage") != "drafted":
        raise DetectionError("Ask for changes after a draft exists.")
    _path, data, digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    previous = current_revision(dac)
    suggestions = await complete_draft(
        rule_file=data,
        alerts=_alerts_for_draft(request, dac),
        feedback=text,
        previous={
            "rationale": previous.get("rationale"),
            "exceptions": previous.get("exceptions"),
            "notes": previous.get("notes"),
        },
        request_id=request.id,
        command="detection revise",
    )
    revision = {"at": _now(), "feedback": text, **suggestions}
    revisions = list(dac.get("revisions") or [])
    revisions.append(revision)
    dac["revisions"] = revisions
    dac["current_revision"] = len(revisions) - 1
    dac["file_sha256"] = digest
    dac["stage"] = "drafted"
    return _save(request, dac)


def implement(request_id: str) -> ApprovalRequest:
    request = get_review(request_id)
    if request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Implement is only available while the review is open.")
    dac = _dac(request)
    path, data, _digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    expected = str(dac.get("file_sha256") or "")
    rule_id = str(dac.get("rule_id") or "")
    if dac.get("kind") == "disable":
        result = write_disabled(path, data, expected)
    else:
        revision = current_revision(dac)
        cards = revision.get("exceptions") or []
        items = data.get("exception_items") if isinstance(data.get("exception_items"), list) else []
        validate_checked(cards, existing_items=items, evidence_fields=list(dac.get("evidence_fields") or []))
        result = write_exceptions(path, data, cards, expected, rule_id)
    comment = f"Implemented into {result.get('file')}"
    archived = get_queue().acknowledge(request.id, comment=comment)
    stored = _dac(archived)
    stored["stage"] = "implemented"
    stored["result"] = {key: value for key, value in result.items() if key != "exception_items"}
    saved = _save(archived, stored)
    saved.execution_result = {
        "success": True,
        "implemented": True,
        "message": comment,
        "file": result.get("file"),
    }
    return get_queue().store.put(saved)


def reject(request_id: str, comment: str = "") -> ApprovalRequest:
    request = get_review(request_id)
    if request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("This review is already closed.")
    ignored = get_queue().ignore(request.id, comment=comment or "Rejected in Detection as Code")
    dac = _dac(ignored)
    dac["stage"] = "rejected"
    return _save(ignored, dac)
