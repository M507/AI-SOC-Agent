"""Review lifecycle for Detection as Code notes.

Fine-tune notes carry ``dac.kind`` exceptions/disable. Visibility notes may
carry ``dac.kind=new_rule``. Draft / Revise / Send-to-Review call the model.
Implement is the only rule-file writer (then Kibana sync). See
documentation/detection-as-code.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..approval_queue import get_queue
from ..approval_queue.models import ApprovalRequest, RequestStatus, is_archived
from . import rules_store
from .diff import unified_diff
from .drafting import complete_draft, complete_new_rule_draft
from .errors import DetectionError
from .apply import write_disabled, write_exceptions, write_new_rule
from .alerts import close_alerts_matching_exceptions
from .validation import evaluate_draft_gate, evaluate_new_rule_gate, validate_checked

MAX_AUTO_FIX_ATTEMPTS = 3
_EDITABLE_STAGES = frozenset({"proposed", "drafted", "needs_fix"})
_PROMOTE_GITHUB_DELETE_COMMENT = "Moved to Detection as Code Review in SamiGPT; deleting the tracking issue."
_IMPLEMENT_GITHUB_DELETE_COMMENT = "Implemented in Detection as Code; deleting the tracking issue."


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
        "rationale": "Built from the fields checked on the alert.",
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


def _is_dac_review(item: ApprovalRequest) -> bool:
    """True for fine-tune notes (DaC-capable) or visibility notes already seeded as new_rule."""
    if item.action_type == "fine_tune":
        return True
    if item.action_type == "visibility" and _dac(item).get("kind") == "new_rule":
        return True
    return False


def list_reviews() -> List[ApprovalRequest]:
    items = []
    for item in get_queue().list(queue="detection"):
        dac = _dac(item)
        if not dac:
            continue
        if item.action_type == "fine_tune":
            items.append(item)
        elif item.action_type == "visibility" and dac.get("kind") == "new_rule":
            items.append(item)
    return items


def get_review(request_id: str) -> ApprovalRequest:
    request = get_queue().get(request_id)
    if request is None or not _is_dac_review(request):
        raise DetectionError("Review not found.", status_code=404)
    return request


def _diff_for(request: ApprovalRequest, dac: Dict[str, Any]) -> str:
    if dac.get("kind") == "new_rule":
        revision = current_revision(dac)
        proposed = revision.get("proposed_rule")
        if not isinstance(proposed, dict):
            return ""
        after_doc = {
            "_dac": {
                "status": "enabled",
                "rule_id": dac.get("rule_id") or "",
                "name": proposed.get("name") or "",
                "origin": "sami_visibility_new_rule",
            },
            "rule": proposed,
            "exception_items": [],
        }
        return unified_diff("{}", rules_store.document_text(after_doc), "new_rule.json")

    path, data, _digest = rules_store.load_rule_file(rule_id=dac.get("rule_id") or (request.payload or {}).get("rule_id"))
    before = rules_store.document_text(data)
    if dac.get("kind") == "disable":
        after = rules_store.document_text(rules_store.render_disabled(data))
    else:
        revision = current_revision(dac)
        cards = revision.get("exceptions") or []
        checked = [card for card in cards if isinstance(card, dict) and card.get("selected") is not False]
        from .apply import exception_item

        rule_id = str(dac.get("rule_id") or "")
        additions = [exception_item(rule_id, card) for card in checked]
        after = rules_store.document_text(rules_store.render_with_exceptions(data, additions))
    return unified_diff(before, after, path.name)


def _suggestion_text(request: ApprovalRequest) -> str:
    payload = request.payload or {}
    return str(
        payload.get("suggestion")
        or payload.get("description")
        or request.summary
        or request.rationale
        or ""
    ).strip()


def _analyst_instructions(request: ApprovalRequest, dac: Optional[Dict[str, Any]] = None) -> str:
    """Human focus note from Send to Review (payload or dac copy)."""
    payload = request.payload or {}
    live = dac if isinstance(dac, dict) else _dac(request)
    return str(
        payload.get("analyst_instructions")
        or live.get("analyst_instructions")
        or ""
    ).strip()


def _select_all_exception_cards(dac: Dict[str, Any]) -> None:
    revisions = list(dac.get("revisions") or [])
    if not revisions:
        return
    index = int(dac.get("current_revision") or 0)
    index = max(0, min(index, len(revisions) - 1))
    current = dict(revisions[index])
    cards = []
    for card in current.get("exceptions") or []:
        if not isinstance(card, dict):
            continue
        updated = dict(card)
        updated["selected"] = True
        cards.append(updated)
    current["exceptions"] = cards
    revisions[index] = current
    dac["revisions"] = revisions


def review_view(request: ApprovalRequest) -> Dict[str, Any]:
    dac = _dac(request)
    revision = current_revision(dac)
    overview = {}
    diff = ""
    warnings: List[str] = []
    error = ""
    proposed = revision.get("proposed_rule") if isinstance(revision.get("proposed_rule"), dict) else {}
    try:
        if dac.get("kind") == "new_rule":
            overview = {
                "rule_id": dac.get("rule_id") or "",
                "name": proposed.get("name") or "",
                "severity": proposed.get("severity") or "",
                "language": proposed.get("language") or "",
                "query": proposed.get("query") or "",
                "exception_count": 0,
                "file": dac.get("file") or "",
                "status": "new",
            }
            diff = _diff_for(request, dac)
            gate = evaluate_new_rule_gate(
                revision,
                coverage_check=(request.payload or {}).get("coverage_check")
                if isinstance((request.payload or {}).get("coverage_check"), dict)
                else {},
                require_teaching=False,
            )
            warnings = list(gate.get("warnings") or [])
            if dac.get("stage") in {"drafted", "needs_fix"} and gate.get("errors"):
                warnings = warnings + [f"Gate: {item}" for item in gate.get("errors") or []]
        else:
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
    auto_fix = dac.get("auto_fix") if isinstance(dac.get("auto_fix"), dict) else {}
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
        "rule_name": payload.get("rule_name") or proposed.get("name") or "",
        "suggestion": _suggestion_text(request),
        "analyst_instructions": _analyst_instructions(request, dac),
        "rationale": revision.get("rationale") or request.rationale or "",
        "safe_to_except": revision.get("safe_to_except"),
        "safe_to_create": revision.get("safe_to_create"),
        "notes": revision.get("notes") or "",
        "siem_context": revision.get("siem_context") if isinstance(revision.get("siem_context"), dict) else {},
        "rule_understanding": revision.get("rule_understanding") or "",
        "improvement_plan": list(revision.get("improvement_plan") or [])
        if isinstance(revision.get("improvement_plan"), list)
        else [],
        "exceptions": revision.get("exceptions") or [],
        "proposed_rule": proposed or None,
        "revision_count": len(dac.get("revisions") or []),
        "auto_fix": auto_fix,
        "overview": overview,
        "diff": diff,
        "warnings": warnings,
        "error": error,
        "result": dac.get("result") if isinstance(dac.get("result"), dict) else {},
        "execution_result": request.execution_result
        if isinstance(getattr(request, "execution_result", None), dict)
        else {},
    }


def update_selection(request_id: str, exceptions: List[Dict[str, Any]]) -> ApprovalRequest:
    request = get_review(request_id)
    dac = _dac(request)
    if dac.get("stage") not in _EDITABLE_STAGES:
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


async def draft(
    request_id: str,
    analyst_instructions: Optional[str] = None,
) -> ApprovalRequest:
    request = get_review(request_id)
    if is_archived(request) or request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Draft is only available while the note is open.")
    dac = _dac(request)
    if dac.get("kind") == "disable":
        raise DetectionError("Disable reviews do not call the model.")
    if dac.get("stage") != "proposed":
        raise DetectionError("Draft runs only before the first suggestion.")
    instructions = (analyst_instructions or "").strip() or _analyst_instructions(request, dac)
    if dac.get("kind") == "new_rule":
        suggestions = await complete_new_rule_draft(
            suggestion=_suggestion_text(request),
            suggestion_title=request.title,
            coverage_check=(request.payload or {}).get("coverage_check")
            if isinstance((request.payload or {}).get("coverage_check"), dict)
            else {},
            source=str((request.payload or {}).get("source") or ""),
            alerts=_alerts_for_draft(request, dac),
            cluster_id=request.cluster_id,
            request_id=request.id,
            command="detection new_rule draft",
            analyst_instructions=instructions or None,
        )
        revision = {"at": _now(), "feedback": "", **suggestions}
        dac["stage"] = "drafted"
        dac["revisions"] = [revision]
        dac["current_revision"] = 0
        return _save(request, dac)

    path, data, digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    suggestions = await complete_draft(
        rule_file=data,
        alerts=_alerts_for_draft(request, dac),
        suggestion=_suggestion_text(request),
        suggestion_title=request.title,
        cluster_id=request.cluster_id,
        request_id=request.id,
        command="detection draft",
        analyst_instructions=instructions or None,
    )
    revision = {"at": _now(), "feedback": "", **suggestions}
    dac["stage"] = "drafted"
    dac["file"] = str(path)
    dac["file_sha256"] = digest
    dac["revisions"] = [revision]
    dac["current_revision"] = 0
    return _save(request, dac)


async def revise(
    request_id: str,
    feedback: str,
    exceptions: Optional[List[Dict[str, Any]]] = None,
    analyst_instructions: Optional[str] = None,
) -> ApprovalRequest:
    text = (feedback or "").strip()
    if not text:
        raise DetectionError("Tell the model what to change.")
    if exceptions is not None:
        update_selection(request_id, exceptions)
    request = get_review(request_id)
    dac = _dac(request)
    if dac.get("kind") == "disable":
        raise DetectionError("Disable reviews do not call the model.")
    if dac.get("stage") not in {"drafted", "needs_fix"}:
        raise DetectionError("Ask for changes after a draft exists.")
    instructions = (analyst_instructions or "").strip() or _analyst_instructions(request, dac)
    previous = current_revision(dac)
    if dac.get("kind") == "new_rule":
        suggestions = await complete_new_rule_draft(
            suggestion=_suggestion_text(request),
            suggestion_title=request.title,
            coverage_check=(request.payload or {}).get("coverage_check")
            if isinstance((request.payload or {}).get("coverage_check"), dict)
            else {},
            source=str((request.payload or {}).get("source") or ""),
            alerts=_alerts_for_draft(request, dac),
            feedback=text,
            previous={
                "rationale": previous.get("rationale"),
                "proposed_rule": previous.get("proposed_rule"),
                "notes": previous.get("notes"),
                "improvement_plan": previous.get("improvement_plan"),
                "safe_to_create": previous.get("safe_to_create"),
            },
            cluster_id=request.cluster_id,
            request_id=request.id,
            command="detection new_rule revise",
            analyst_instructions=instructions or None,
        )
        revision = {"at": _now(), "feedback": text, **suggestions}
        revisions = list(dac.get("revisions") or [])
        revisions.append(revision)
        dac["revisions"] = revisions
        dac["current_revision"] = len(revisions) - 1
        dac["stage"] = "drafted"
        return _save(request, dac)

    _path, data, digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    suggestions = await complete_draft(
        rule_file=data,
        alerts=_alerts_for_draft(request, dac),
        feedback=text,
        previous={
            "rationale": previous.get("rationale"),
            "exceptions": previous.get("exceptions"),
            "notes": previous.get("notes"),
            "siem_context": previous.get("siem_context"),
            "rule_understanding": previous.get("rule_understanding"),
            "improvement_plan": previous.get("improvement_plan"),
        },
        suggestion=_suggestion_text(request),
        suggestion_title=request.title,
        cluster_id=request.cluster_id,
        request_id=request.id,
        command="detection revise",
        analyst_instructions=instructions or None,
    )
    revision = {"at": _now(), "feedback": text, **suggestions}
    revisions = list(dac.get("revisions") or [])
    revisions.append(revision)
    dac["revisions"] = revisions
    dac["current_revision"] = len(revisions) - 1
    dac["file_sha256"] = digest
    dac["stage"] = "drafted"
    return _save(request, dac)


def _gate_feedback(errors: List[str]) -> str:
    bullets = "\n".join(f"- {item}" for item in errors)
    return (
        "The previous fine-tune draft failed validation. Fix every item below. "
        "Keep exceptions narrow, evidence-based, and explain the SIEM signal "
        "and improvement plan.\n"
        f"{bullets}"
    )


async def promote_from_request(
    request_id: str,
    analyst_note: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a Fine-tune Requests note into DaC Review with auto draft+validate.

    On success: stage ``drafted``, cards pre-selected, linked GitHub issue deleted.
    After three failed model attempts: stage ``needs_fix``, GitHub left open,
    full attempt log retained for human fix.
    """
    request = get_review(request_id)
    if is_archived(request) or request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Send to Review is only available while the fine-tune note is open.")
    if request.action_type != "fine_tune":
        raise DetectionError("Only fine-tune notes can be sent to Detection as Code Review.")

    dac = _dac(request)
    stage = str(dac.get("stage") or "")
    auto_fix = dac.get("auto_fix") if isinstance(dac.get("auto_fix"), dict) else {}
    if stage == "drafted" and auto_fix.get("passed"):
        return review_view(request)
    if stage in {"implemented", "rejected"}:
        raise DetectionError("This fine-tune review is already closed.")

    payload = dict(request.payload or {})
    instructions = (analyst_note or "").strip()
    if instructions:
        payload["analyst_instructions"] = instructions
    rule_id = str(dac.get("rule_id") or payload.get("rule_id") or "")
    rule_name = str(payload.get("rule_name") or "")
    if not rule_id and not rule_name:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        rule_id = str(rule.get("rule_id") or "")
        rule_name = str(rule.get("name") or "")
    try:
        path, data, digest = ensure_rule_snapshot(rule_id, rule_name)
    except DetectionError:
        raise
    except Exception as exc:
        raise DetectionError(f"No matching Home Lab rule for this fine-tune: {exc}", status_code=400) from exc

    resolved_id = str((data.get("_dac") or {}).get("rule_id") or (data.get("rule") or {}).get("rule_id") or rule_id)
    excerpt_name = str((data.get("rule") or {}).get("name") or rule_name or resolved_id)
    should_seed = (not dac) or (stage in {"", "proposed"} and not dac.get("revisions"))
    if should_seed:
        dac = _seed_dac(
            kind="exceptions",
            stage="proposed",
            path=path,
            digest=digest,
            rule_id=resolved_id,
            evidence_fields=list((dac or {}).get("evidence_fields") or []),
        )
    else:
        dac = dict(dac)
        dac["kind"] = dac.get("kind") or "exceptions"
        dac["file"] = str(path)
        dac["file_sha256"] = digest
        dac["rule_id"] = resolved_id
        if dac.get("stage") not in {"proposed", "drafted", "needs_fix"}:
            dac["stage"] = "proposed"
    if instructions:
        dac["analyst_instructions"] = instructions
    elif payload.get("analyst_instructions"):
        dac["analyst_instructions"] = str(payload.get("analyst_instructions") or "").strip()

    payload["rule_id"] = resolved_id
    payload["rule_name"] = excerpt_name
    if not payload.get("suggestion"):
        payload["suggestion"] = _suggestion_text(request)
    request.payload = payload
    request = _save(request, dac)
    instructions = _analyst_instructions(request, dac)

    attempts: List[Dict[str, Any]] = list((dac.get("auto_fix") or {}).get("attempts") or [])
    last_errors: List[str] = []

    for attempt_number in range(1, MAX_AUTO_FIX_ATTEMPTS + 1):
        live = _dac(request)
        kind = "draft" if live.get("stage") == "proposed" else "revise"
        try:
            if kind == "draft":
                request = await draft(request.id, analyst_instructions=instructions or None)
            else:
                request = await revise(
                    request.id,
                    _gate_feedback(last_errors or ["Improve the fine-tune draft."]),
                    analyst_instructions=instructions or None,
                )
        except DetectionError as exc:
            last_errors = [str(exc)]
            attempts.append({
                "at": _now(),
                "kind": kind,
                "errors": last_errors,
                "warnings": [],
                "safe_to_except": None,
                "exception_count": 0,
            })
            dac = _dac(request)
            dac["auto_fix"] = {"attempts": attempts, "passed": False, "max_attempts": MAX_AUTO_FIX_ATTEMPTS}
            request = _save(request, dac)
            continue

        dac = _dac(request)
        # Gate assumes the AI cards will be kept; select them before diffing.
        _select_all_exception_cards(dac)
        request = _save(request, dac)
        dac = _dac(request)
        revision = current_revision(dac)
        diff_text = ""
        existing_items: List[Dict[str, Any]] = (
            data.get("exception_items") if isinstance(data.get("exception_items"), list) else []
        )
        try:
            diff_text = _diff_for(request, dac)
            detail = rules_store.rule_detail(resolved_id)
            existing_items = detail.get("exception_items") or existing_items
        except DetectionError as exc:
            last_errors = [str(exc)]

        gate = evaluate_draft_gate(
            revision,
            existing_items=existing_items,
            evidence_fields=list(dac.get("evidence_fields") or []),
            diff_text=diff_text,
            require_teaching=True,
        )
        attempts.append({
            "at": _now(),
            "kind": kind,
            "errors": list(gate.get("errors") or []),
            "warnings": list(gate.get("warnings") or []),
            "safe_to_except": revision.get("safe_to_except"),
            "exception_count": len(revision.get("exceptions") or []),
        })
        if gate.get("ok"):
            dac["stage"] = "drafted"
            dac["auto_fix"] = {
                "attempts": attempts,
                "passed": True,
                "max_attempts": MAX_AUTO_FIX_ATTEMPTS,
                "passed_on_attempt": attempt_number,
            }
            request = _save(request, dac)
            github = get_queue().delete_linked_github_issue(
                request,
                comment=_PROMOTE_GITHUB_DELETE_COMMENT,
            )
            request = get_queue().store.put(request)
            view = review_view(request)
            view["github"] = github
            return view

        last_errors = list(gate.get("errors") or []) or ["Draft failed validation."]
        dac["auto_fix"] = {"attempts": attempts, "passed": False, "max_attempts": MAX_AUTO_FIX_ATTEMPTS}
        request = _save(request, dac)

    dac = _dac(request)
    dac["stage"] = "needs_fix"
    dac["auto_fix"] = {
        "attempts": attempts,
        "passed": False,
        "max_attempts": MAX_AUTO_FIX_ATTEMPTS,
        "exhausted": True,
    }
    request = _save(request, dac)
    view = review_view(request)
    view["error"] = view.get("error") or (
        "AI draft failed validation after 3 tries — review the attempt log and fix or Reject."
    )
    return view


def _open_visibility_new_rule(alert_id: str, title: str = "") -> Optional[ApprovalRequest]:
    alert = str(alert_id or "").strip()
    title_l = (title or "").strip().lower()
    for item in get_queue().list(queue="detection"):
        if item.action_type != "visibility" or is_archived(item):
            continue
        dac = _dac(item)
        if dac.get("kind") != "new_rule":
            continue
        if dac.get("stage") in {"implemented", "rejected"}:
            continue
        payload = item.payload or {}
        item_alert = str(payload.get("alert_id") or "").strip()
        if alert and item_alert == alert:
            return item
        if not alert and title_l and (item.title or "").strip().lower() == title_l:
            return item
    return None


def _new_rule_gate_feedback(errors: List[str]) -> str:
    bullets = "\n".join(f"- {item}" for item in errors)
    return (
        "The previous new-rule draft failed validation. Fix every item below. "
        "Only type=query rules are allowed; do not duplicate catalog coverage.\n"
        f"{bullets}"
    )


async def promote_visibility_from_request(
    request_id: str,
    analyst_note: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a Visibility note into DaC Review as dac.kind=new_rule."""
    request = get_queue().get(request_id)
    if request is None:
        raise DetectionError("Request not found.", status_code=404)
    if is_archived(request) or request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Send to Review is only available while the visibility note is open.")
    if request.action_type != "visibility":
        raise DetectionError("Only visibility notes can be sent for new-rule Detection as Code Review.")

    payload = dict(request.payload or {})
    coverage = payload.get("coverage_check") if isinstance(payload.get("coverage_check"), dict) else {}
    if coverage.get("likely_covered"):
        matches = coverage.get("matching_rules") or []
        hint = ""
        if isinstance(matches, list) and matches and isinstance(matches[0], dict):
            hint = f" Matching rule: {matches[0].get('name') or matches[0].get('rule_id') or ''}."
        raise DetectionError(
            "Catalog coverage check says this behavior is likely already covered."
            f"{hint} Use Fine-tune on that rule instead of creating a new one.",
            status_code=400,
        )

    dac = _dac(request)
    stage = str(dac.get("stage") or "")
    auto_fix = dac.get("auto_fix") if isinstance(dac.get("auto_fix"), dict) else {}
    if stage == "drafted" and auto_fix.get("passed"):
        return review_view(request)
    if stage in {"implemented", "rejected"}:
        raise DetectionError("This visibility review is already closed.")

    existing = _open_visibility_new_rule(str(payload.get("alert_id") or ""), request.title)
    if existing is not None and existing.id != request.id and _dac(existing).get("stage") not in {
        "implemented",
        "rejected",
        "",
    }:
        # Prefer updating the already-open new_rule review for this alert/theme.
        request = existing
        payload = dict(request.payload or {})
        dac = _dac(request)

    instructions = (analyst_note or "").strip()
    if instructions:
        payload["analyst_instructions"] = instructions
    rule_id = str(dac.get("rule_id") or payload.get("rule_id") or uuid4())
    should_seed = (not dac) or (stage in {"", "proposed"} and not dac.get("revisions"))
    if should_seed:
        dac = _seed_dac(
            kind="new_rule",
            stage="proposed",
            path="",
            digest="",
            rule_id=rule_id,
            evidence_fields=list((dac or {}).get("evidence_fields") or []),
        )
    else:
        dac = dict(dac)
        dac["kind"] = "new_rule"
        dac["rule_id"] = dac.get("rule_id") or rule_id
        if dac.get("stage") not in {"proposed", "drafted", "needs_fix"}:
            dac["stage"] = "proposed"
    if instructions:
        dac["analyst_instructions"] = instructions
    elif payload.get("analyst_instructions"):
        dac["analyst_instructions"] = str(payload.get("analyst_instructions") or "").strip()
    if not payload.get("suggestion"):
        payload["suggestion"] = _suggestion_text(request)
    request.payload = payload
    request = _save(request, dac)
    instructions = _analyst_instructions(request, dac)

    attempts: List[Dict[str, Any]] = list((dac.get("auto_fix") or {}).get("attempts") or [])
    last_errors: List[str] = []

    for attempt_number in range(1, MAX_AUTO_FIX_ATTEMPTS + 1):
        live = _dac(request)
        kind = "draft" if live.get("stage") == "proposed" else "revise"
        try:
            if kind == "draft":
                request = await draft(request.id, analyst_instructions=instructions or None)
            else:
                request = await revise(
                    request.id,
                    _new_rule_gate_feedback(last_errors or ["Improve the new-rule draft."]),
                    analyst_instructions=instructions or None,
                )
        except DetectionError as exc:
            last_errors = [str(exc)]
            attempts.append({
                "at": _now(),
                "kind": kind,
                "errors": last_errors,
                "warnings": [],
                "safe_to_create": None,
            })
            dac = _dac(request)
            dac["auto_fix"] = {"attempts": attempts, "passed": False, "max_attempts": MAX_AUTO_FIX_ATTEMPTS}
            request = _save(request, dac)
            continue

        dac = _dac(request)
        revision = current_revision(dac)
        gate = evaluate_new_rule_gate(
            revision,
            coverage_check=payload.get("coverage_check")
            if isinstance(payload.get("coverage_check"), dict)
            else {},
            require_teaching=True,
        )
        attempts.append({
            "at": _now(),
            "kind": kind,
            "errors": list(gate.get("errors") or []),
            "warnings": list(gate.get("warnings") or []),
            "safe_to_create": revision.get("safe_to_create"),
        })
        if gate.get("ok"):
            dac["stage"] = "drafted"
            dac["auto_fix"] = {
                "attempts": attempts,
                "passed": True,
                "max_attempts": MAX_AUTO_FIX_ATTEMPTS,
                "passed_on_attempt": attempt_number,
            }
            request = _save(request, dac)
            github = get_queue().delete_linked_github_issue(
                request,
                comment=_PROMOTE_GITHUB_DELETE_COMMENT,
            )
            request = get_queue().store.put(request)
            view = review_view(request)
            view["github"] = github
            return view

        last_errors = list(gate.get("errors") or []) or ["Draft failed validation."]
        dac["auto_fix"] = {"attempts": attempts, "passed": False, "max_attempts": MAX_AUTO_FIX_ATTEMPTS}
        request = _save(request, dac)

    dac = _dac(request)
    dac["stage"] = "needs_fix"
    dac["auto_fix"] = {
        "attempts": attempts,
        "passed": False,
        "max_attempts": MAX_AUTO_FIX_ATTEMPTS,
        "exhausted": True,
    }
    request = _save(request, dac)
    view = review_view(request)
    view["error"] = view.get("error") or (
        "AI draft failed validation after 3 tries — review the attempt log and fix or Reject."
    )
    return view


def _card_signature(card: Dict[str, Any]) -> frozenset:
    return frozenset(
        (str(entry.get("field") or "").strip(), str(entry.get("value")))
        for entry in (card.get("entries") or [])
        if isinstance(entry, dict) and str(entry.get("field") or "").strip()
    )


def _item_signature(item: Dict[str, Any]) -> frozenset:
    return frozenset(
        (str(entry.get("field") or "").strip(), str(entry.get("value")))
        for entry in (item.get("entries") or [])
        if isinstance(entry, dict) and str(entry.get("field") or "").strip()
    )


def _additions_already_on_disk(data: Dict[str, Any], cards: List[Dict[str, Any]]) -> bool:
    existing = {
        _item_signature(item)
        for item in (data.get("exception_items") or [])
        if isinstance(item, dict)
    }
    selected = [card for card in cards if isinstance(card, dict) and card.get("selected") is not False]
    if not selected:
        return False
    return all(_card_signature(card) in existing for card in selected)


def implement(request_id: str) -> ApprovalRequest:
    request = get_review(request_id)
    if request.status != RequestStatus.INFORMATIONAL:
        raise DetectionError("Implement is only available while the review is open.")
    dac = _dac(request)

    if dac.get("kind") == "new_rule":
        revision = current_revision(dac)
        coverage = (request.payload or {}).get("coverage_check")
        gate = evaluate_new_rule_gate(
            revision,
            coverage_check=coverage if isinstance(coverage, dict) else {},
            require_teaching=True,
        )
        if not gate.get("ok"):
            raise DetectionError("; ".join(gate.get("errors") or ["New-rule draft failed validation."]))
        proposed = revision.get("proposed_rule")
        if not isinstance(proposed, dict):
            raise DetectionError("No proposed_rule to implement.")
        if dac.get("rule_id") and not proposed.get("rule_id"):
            proposed = dict(proposed)
            proposed["rule_id"] = dac.get("rule_id")
        result = write_new_rule(proposed)
        path = result.get("file")
        digest = result.get("file_sha256")
        rule_id = str(result.get("rule_id") or dac.get("rule_id") or "")
        dac["rule_id"] = rule_id
        dac["file_sha256"] = str(digest or "")
        dac["file"] = str(path or "")
        request = _save(request, dac)

        from ...core.elastic_clusters import client_for_id
        from .elastic_sync import push_rule_after_implement

        client = client_for_id(request.cluster_id)
        try:
            sync = push_rule_after_implement(client, file_path=str(path))
        except DetectionError as exc:
            dac["sync_error"] = str(exc)
            _save(request, dac)
            raise
        result = {**result, **sync, "file": sync.get("file") or result.get("file")}
        comment = f"Created new rule in {result.get('file')} and synced to Elastic"
        github = get_queue().delete_linked_github_issue(
            request,
            comment=_IMPLEMENT_GITHUB_DELETE_COMMENT,
        )
        if github.get("attempted"):
            request = get_queue().store.put(request)
        archived = get_queue().acknowledge(request.id, comment=comment)
        stored = _dac(archived)
        stored["stage"] = "implemented"
        stored["file_sha256"] = result.get("file_sha256") or stored.get("file_sha256")
        stored.pop("sync_error", None)
        stored["result"] = {key: value for key, value in result.items() if key != "exception_items"}
        saved = _save(archived, stored)
        saved.execution_result = {
            "success": True,
            "implemented": True,
            "synced": True,
            "created": True,
            "message": comment,
            "file": result.get("file"),
            "revision": result.get("revision"),
            "github": github,
            "alerts_closed": [],
            "alerts_close_failed": [],
        }
        return get_queue().store.put(saved)

    path, data, digest = rules_store.load_rule_file(rule_id=str(dac.get("rule_id") or ""))
    expected = str(dac.get("file_sha256") or "")
    rule_id = str(dac.get("rule_id") or "")
    if dac.get("kind") == "disable":
        if str((data.get("_dac") or {}).get("status") or "") == "disabled" and not str(path.name).startswith("[enabled]_"):
            result = {"file": str(path), "file_sha256": digest, "status": "disabled", "skipped_write": True}
        else:
            result = write_disabled(path, data, expected)
    else:
        revision = current_revision(dac)
        cards = revision.get("exceptions") or []
        items = data.get("exception_items") if isinstance(data.get("exception_items"), list) else []
        validate_checked(
            cards,
            existing_items=[] if _additions_already_on_disk(data, cards) else items,
            evidence_fields=list(dac.get("evidence_fields") or []),
        )
        if _additions_already_on_disk(data, cards):
            result = {"file": str(path), "file_sha256": digest, "added": 0, "skipped_write": True}
        else:
            result = write_exceptions(path, data, cards, expected, rule_id)

    # Persist the post-write digest so a failed Elastic push can be retried.
    dac["file_sha256"] = str(result.get("file_sha256") or digest)
    dac["file"] = str(result.get("file") or path)
    request = _save(request, dac)

    # Same deploy step as Home-Lab-Rules Fine-tune & Deploy: local write, then push to Kibana.
    from ...core.elastic_clusters import client_for_id
    from .elastic_sync import push_rule_after_implement

    client = client_for_id(request.cluster_id)
    try:
        sync = push_rule_after_implement(client, file_path=str(result.get("file") or path))
    except DetectionError as exc:
        dac["sync_error"] = str(exc)
        _save(request, dac)
        raise
    result = {**result, **sync, "file": sync.get("file") or result.get("file")}

    # Exception Implement: close open alerts that match selected cards (best-effort).
    alerts_closed: Dict[str, Any] = {"updated": [], "failed": [], "matched": []}
    if dac.get("kind") != "disable":
        revision = current_revision(dac)
        cards = revision.get("exceptions") or []
        try:
            alerts_closed = close_alerts_matching_exceptions(
                client,
                rule_id=rule_id,
                exception_cards=cards if isinstance(cards, list) else [],
            )
        except Exception as exc:  # noqa: BLE001 — never undo a successful write/sync
            alerts_closed = {
                "updated": [],
                "failed": [{"alert_id": "", "error": str(exc)}],
                "matched": [],
            }
        result["alerts_closed"] = alerts_closed.get("updated") or []
        result["alerts_close_failed"] = alerts_closed.get("failed") or []

    comment = f"Implemented into {result.get('file')} and synced to Elastic"
    closed_n = len(result.get("alerts_closed") or [])
    failed_n = len(result.get("alerts_close_failed") or [])
    if dac.get("kind") != "disable":
        comment = f"{comment}; closed {closed_n} matching open alert(s)"
        if failed_n:
            comment = f"{comment} ({failed_n} close failure(s))"
    # Delete GitHub before archive when still linked (idempotent if Send already deleted).
    github = get_queue().delete_linked_github_issue(
        request,
        comment=_IMPLEMENT_GITHUB_DELETE_COMMENT,
    )
    if github.get("attempted"):
        request = get_queue().store.put(request)
    archived = get_queue().acknowledge(request.id, comment=comment)
    stored = _dac(archived)
    stored["stage"] = "implemented"
    stored["file_sha256"] = result.get("file_sha256") or stored.get("file_sha256")
    stored.pop("sync_error", None)
    stored["result"] = {key: value for key, value in result.items() if key != "exception_items"}
    saved = _save(archived, stored)
    saved.execution_result = {
        "success": True,
        "implemented": True,
        "synced": True,
        "message": comment,
        "file": result.get("file"),
        "revision": result.get("revision"),
        "github": github,
        "alerts_closed": result.get("alerts_closed") or [],
        "alerts_close_failed": result.get("alerts_close_failed") or [],
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
