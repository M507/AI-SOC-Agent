"""MCP helpers that file approval requests instead of executing gated tools."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ...core.logging import get_logger
from .catalog import spec_for_mcp_tool
from .service import get_queue

logger = get_logger("sami.approval_queue.mcp")


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
    logger.info(
        "Queued %s as approval request %s (%s)",
        tool_name,
        request.id,
        spec.action_type,
    )
    return {
        "queued": True,
        "success": True,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "message": (
            f"{spec.label} was filed for analyst approval in the SamiGPT Requests view "
            f"(id {request.id}). It will not run until it is approved."
        ),
    }


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
    return {
        "success": True,
        "queued": True,
        "request_id": request.id,
        "action_type": request.action_type,
        "status": request.status.value,
        "message": (
            f"Filed {request.title} for analyst approval in the SamiGPT Requests view "
            f"(id {request.id})."
        ),
    }
