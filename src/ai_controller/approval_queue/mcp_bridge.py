"""MCP helpers that file approval requests instead of executing gated tools."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ...core.logging import get_logger
from .catalog import spec_for_mcp_tool
from .service import get_queue

logger = get_logger("sami.approval_queue.mcp")


def _mirror_recommendation_to_github(request, action_type: str) -> Optional[Dict[str, Any]]:
    """
    When ENG is GitHub Issues, also open an issue for fine-tune / visibility notes.
    """
    try:
        from .clients import resolve_clients
        from ...integrations.eng.github.github_client import GitHubClient
    except Exception:
        return None

    bundle = resolve_clients(getattr(request, "cluster_id", None))
    eng = bundle.eng
    if not isinstance(eng, GitHubClient):
        return None

    title = str(getattr(request, "title", None) or action_type)
    body_parts = []
    summary = str(getattr(request, "summary", None) or "").strip()
    if summary:
        body_parts.append(summary)
    payload = getattr(request, "payload", None) or {}
    suggestion = payload.get("suggestion") or payload.get("description")
    if suggestion and str(suggestion).strip() and str(suggestion).strip() != summary:
        body_parts.append(str(suggestion).strip())
    rule = payload.get("rule")
    if isinstance(rule, dict):
        rule_name = rule.get("name") or rule.get("rule_id")
        if rule_name:
            body_parts.append(f"**Rule:** `{rule_name}`")
        query = rule.get("query")
        if query:
            body_parts.append(f"```\n{str(query)[:2000]}\n```")
    coverage = payload.get("coverage_check")
    if isinstance(coverage, dict) and coverage.get("note"):
        body_parts.append(f"**Coverage:** {coverage.get('status')} — {coverage.get('note')}")
    if payload.get("suggested_path"):
        body_parts.append(f"**Suggested path:** `{payload.get('suggested_path')}`")
    body_parts.append(f"_Filed from SamiGPT request `{request.id}`_")
    body = "\n\n".join(body_parts) if body_parts else title

    try:
        if action_type == "fine_tune":
            issue = eng.create_fine_tuning_recommendation(title=title, description=body)
        elif action_type == "runbook_gap":
            if hasattr(eng, "create_runbook_recommendation"):
                issue = eng.create_runbook_recommendation(title=title, description=body)
            else:
                issue = eng.create_visibility_recommendation(
                    title=f"[Runbook] {title}",
                    description=body,
                )
        else:
            issue = eng.create_visibility_recommendation(title=title, description=body)
    except Exception as exc:
        logger.warning("Failed to mirror %s to GitHub Issues: %s", action_type, exc)
        return {"success": False, "error": str(exc)}

    return {
        "success": True,
        "provider": "github",
        "repository": eng.repository,
        "issue": {
            "number": issue.get("number"),
            "url": issue.get("html_url"),
            "title": issue.get("title"),
            "state": issue.get("state"),
        },
    }


def _result_message(spec, request, outcome: str, informational: bool, engineering=None) -> str:
    if outcome == "deduplicated":
        where = "Notes" if informational else "Approvals"
        return (
            f"{spec.label} already has an open request under Requests → {where} "
            f"(id {request.id}). Do not file another; reuse this request_id."
        )
    if outcome == "updated":
        where = "Notes" if informational else "Approvals"
        return (
            f"Updated the existing open {spec.label} under Requests → {where} "
            f"(id {request.id}) with richer details. Do not file another."
        )
    if informational:
        message = (
            f"{spec.label} was filed under Requests → Notes "
            f"(id {request.id}). There is nothing to approve — it is a suggestion only."
        )
        if engineering and engineering.get("success") and engineering.get("issue"):
            message += (
                f" Also opened GitHub issue #{engineering['issue'].get('number')} "
                f"({engineering['issue'].get('url')})."
            )
        elif engineering and not engineering.get("success"):
            message += f" GitHub Issues mirror failed: {engineering.get('error')}."
        return message
    message = (
        f"{spec.label} was filed under Requests → Approvals "
        f"(id {request.id}). It will not run until it is approved."
    )
    if request.action_type in {"isolate_endpoint", "release_isolation"}:
        message += (
            " Host isolation is currently disabled — Approve will not call "
            "Elastic Defend or EDR."
        )
    return message


def enqueue_gated_tool(
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    cluster_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    If `tool_name` is a high-impact action, file it in the Requests queue
    and return an MCP-friendly result. Returns None when the tool should run now.
    """
    spec = spec_for_mcp_tool(tool_name)
    if spec is None:
        return None
    outcome = get_queue().enqueue_from_mcp_tool(
        tool_name,
        arguments or {},
        cluster_id=cluster_id,
        session_id=session_id,
    )
    request = outcome.request
    informational = spec.execution == "informational"
    logger.info(
        "Queued %s as approval request %s (%s, outcome=%s)",
        tool_name,
        request.id,
        spec.action_type,
        outcome.outcome,
    )
    engineering = None
    if (
        informational
        and outcome.outcome == "created"
        and request.action_type in {"fine_tune", "visibility", "runbook_gap"}
    ):
        engineering = _mirror_recommendation_to_github(request, request.action_type)
        if engineering and engineering.get("success"):
            try:
                request = get_queue().attach_engineering(request.id, engineering)
            except Exception as exc:
                logger.warning("Could not persist GitHub mirror on request %s: %s", request.id, exc)

    result = {
        "queued": True,
        "success": True,
        "informational": informational,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "outcome": outcome.outcome,
        "deduplicated": outcome.outcome == "deduplicated",
        "updated": outcome.outcome == "updated",
        "message": _result_message(spec, request, outcome.outcome, informational, engineering),
        "payload": {
            key: request.payload.get(key)
            for key in (
                "rule_found",
                "rule",
                "coverage_check",
                "suggestion",
                "existing_case_runbooks",
                "near_matches",
                "suggested_path",
            )
            if key in request.payload
        },
    }
    if engineering:
        result["engineering"] = engineering
    return result


def create_request_from_tool_args(args: Dict[str, Any], cluster_id: Optional[str] = None) -> Dict[str, Any]:
    """Handle the create_approval_request MCP tool."""
    follow_ups = args.get("follow_ups")
    if isinstance(follow_ups, str):
        import json

        try:
            follow_ups = json.loads(follow_ups)
        except json.JSONDecodeError:
            follow_ups = None
    outcome = get_queue().enqueue(
        action_type=str(args["action_type"]),
        title=str(args.get("title") or args["action_type"]),
        summary=str(args.get("summary") or ""),
        payload=args.get("payload") if isinstance(args.get("payload"), dict) else {},
        rationale=str(args.get("rationale") or ""),
        cluster_id=args.get("cluster_id") or cluster_id,
        session_id=args.get("session_id"),
        question=args.get("question"),
        follow_ups=follow_ups if isinstance(follow_ups, dict) else None,
        source="mcp",
    )
    request = outcome.request
    from .catalog import get_action_spec

    spec = get_action_spec(request.action_type)
    informational = bool(spec and spec.execution == "informational")
    engineering = None
    if (
        informational
        and outcome.outcome == "created"
        and request.action_type in {"fine_tune", "visibility", "runbook_gap"}
    ):
        engineering = _mirror_recommendation_to_github(request, request.action_type)
        if engineering and engineering.get("success"):
            try:
                request = get_queue().attach_engineering(request.id, engineering)
            except Exception as exc:
                logger.warning("Could not persist GitHub mirror on request %s: %s", request.id, exc)
    label = spec.label if spec else request.action_type
    if outcome.outcome == "deduplicated":
        message = (
            f"{label} already has an open request (id {request.id}). "
            "Do not file another; reuse this request_id."
        )
    elif outcome.outcome == "updated":
        message = (
            f"Updated the existing open {label} (id {request.id}) with richer details."
        )
    elif informational:
        message = (
            f"Filed {request.title} under Requests → Notes "
            f"(id {request.id}). There is nothing to approve — it is a suggestion only."
        )
        if engineering and engineering.get("success") and engineering.get("issue"):
            message += (
                f" Also opened GitHub issue #{engineering['issue'].get('number')} "
                f"({engineering['issue'].get('url')})."
            )
    else:
        message = f"Filed {request.title} under Requests → Approvals (id {request.id})."
        if request.action_type in {"isolate_endpoint", "release_isolation"}:
            message += (
                " Host isolation is currently disabled — Approve will not call "
                "Elastic Defend or EDR."
            )
    result = {
        "success": True,
        "queued": True,
        "informational": informational,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "outcome": outcome.outcome,
        "deduplicated": outcome.outcome == "deduplicated",
        "updated": outcome.outcome == "updated",
        "message": message,
    }
    if engineering:
        result["engineering"] = engineering
    return result


def find_related_requests_from_args(
    args: Optional[Dict[str, Any]] = None,
    cluster_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Handle the find_related_requests MCP tool."""
    args = dict(args or {})
    action_types = args.get("action_types")
    if isinstance(action_types, str):
        action_types = [part.strip() for part in action_types.split(",") if part.strip()]
    if not isinstance(action_types, list):
        action_types = None
    items = get_queue().find_related_requests(
        alert_id=args.get("alert_id"),
        action_type=args.get("action_type"),
        action_types=action_types,
        rule_id=args.get("rule_id"),
        rule_name=args.get("rule_name"),
        query=args.get("query"),
        cluster_id=args.get("cluster_id") or cluster_id,
        open_only=bool(args.get("open_only", True)),
        limit=int(args.get("limit") or 25),
    )
    return {
        "success": True,
        "count": len(items),
        "requests": items,
        "message": (
            f"Found {len(items)} related open request(s). "
            "If one already covers the same alert or the same rule recommendation, "
            "do not file another — cite its request_id instead."
            if items
            else "No related open requests found."
        ),
    }
