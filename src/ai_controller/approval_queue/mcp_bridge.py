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


def enqueue_gated_tool(
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    cluster_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    If `tool_name` is a high-impact action, file it in the Requests queue
    and return an MCP-friendly result. Returns None when the tool should run now.
    """
    spec = spec_for_mcp_tool(tool_name)
    if spec is None:
        return None
    request = get_queue().create_from_mcp_tool(
        tool_name,
        arguments or {},
        cluster_id=cluster_id,
    )
    informational = spec.execution == "informational"
    logger.info(
        "Queued %s as approval request %s (%s)",
        tool_name,
        request.id,
        spec.action_type,
    )
    engineering = None
    if informational and request.action_type in {"fine_tune", "visibility", "runbook_gap"}:
        engineering = _mirror_recommendation_to_github(request, request.action_type)
        if engineering and engineering.get("success"):
            try:
                request = get_queue().attach_engineering(request.id, engineering)
            except Exception as exc:
                logger.warning("Could not persist GitHub mirror on request %s: %s", request.id, exc)

    if informational:
        message = (
            f"{spec.label} was filed as informational in the SamiGPT Requests view "
            f"(id {request.id}). There is nothing to approve — it is a suggestion only."
        )
        if engineering and engineering.get("success") and engineering.get("issue"):
            message += (
                f" Also opened GitHub issue #{engineering['issue'].get('number')} "
                f"({engineering['issue'].get('url')})."
            )
        elif engineering and not engineering.get("success"):
            message += f" GitHub Issues mirror failed: {engineering.get('error')}."
    else:
        message = (
            f"{spec.label} was filed for analyst approval in the SamiGPT Requests view "
            f"(id {request.id}). It will not run until it is approved."
        )
    result = {
        "queued": True,
        "success": True,
        "informational": informational,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "message": message,
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
    request = get_queue().create(
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
    from .catalog import get_action_spec

    spec = get_action_spec(request.action_type)
    informational = bool(spec and spec.execution == "informational")
    engineering = None
    if informational and request.action_type in {"fine_tune", "visibility", "runbook_gap"}:
        engineering = _mirror_recommendation_to_github(request, request.action_type)
        if engineering and engineering.get("success"):
            try:
                request = get_queue().attach_engineering(request.id, engineering)
            except Exception as exc:
                logger.warning("Could not persist GitHub mirror on request %s: %s", request.id, exc)
    if informational:
        message = (
            f"Filed {request.title} as informational in the SamiGPT Requests view "
            f"(id {request.id}). There is nothing to approve — it is a suggestion only."
        )
    else:
        message = (
            f"Filed {request.title} for analyst approval in the SamiGPT Requests view "
            f"(id {request.id})."
        )
    result = {
        "success": True,
        "queued": True,
        "informational": informational,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "message": message,
    }
    if engineering:
        result["engineering"] = engineering
    return result
