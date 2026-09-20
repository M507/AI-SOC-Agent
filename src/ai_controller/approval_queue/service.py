"""Create, decide, and execute analyst approval requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ...core.logging import get_logger
from .actions import get_handler
from .catalog import get_action_spec, list_action_specs
from .clients import resolve_clients
from .models import ApprovalRequest, Decision, FollowUpPlan, RequestStatus
from .store import RequestStore

logger = get_logger("sami.approval_queue")

_CRITICAL_FOLLOW_UPS = {"isolate_endpoint", "kill_process", "disable_user", "reset_credentials"}

_queue: Optional["ApprovalQueue"] = None


def init_queue(storage_dir: Optional[str] = None) -> "ApprovalQueue":
    global _queue
    _queue = ApprovalQueue(storage_dir or "data/ai_controller")
    return _queue


def get_queue(storage_dir: Optional[str] = None) -> "ApprovalQueue":
    global _queue
    if _queue is None:
        _queue = ApprovalQueue(storage_dir or "data/ai_controller")
    return _queue


class ApprovalQueue:
    def __init__(self, storage_dir: str = "data/ai_controller") -> None:
        self.store = RequestStore(storage_dir)

    def catalog(self) -> List[Dict[str, Any]]:
        return [spec.to_dict() for spec in list_action_specs()]

    def list(
        self,
        status: Optional[str] = None,
        cluster_id: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        if status == "pending":
            items = [
                item
                for item in self.store.list(cluster_id=cluster_id)
                if item.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}
            ]
            items = [self.ensure_enriched(item) for item in items]
            return sorted(items, key=lambda item: item.created_at, reverse=True)
        parsed = RequestStatus(status) if status else None
        items = self.store.list(status=parsed, cluster_id=cluster_id)
        if parsed in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL} or status is None:
            items = [
                self.ensure_enriched(item)
                if item.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}
                else item
                for item in items
            ]
        return items

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        request = self.store.get(request_id)
        if request is None:
            return None
        if request.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
            return self.ensure_enriched(request)
        return request

    def counts(self) -> Dict[str, int]:
        return {
            "pending": self.store.count(RequestStatus.PENDING) + self.store.count(RequestStatus.INFORMATIONAL),
            "informational": self.store.count(RequestStatus.INFORMATIONAL),
            "all": self.store.count(),
        }

    def create(
        self,
        action_type: str,
        title: str,
        summary: str,
        payload: Optional[Dict[str, Any]] = None,
        rationale: str = "",
        cluster_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source: str = "mcp",
        question: Optional[str] = None,
        follow_ups: Optional[Dict[str, Any]] = None,
        parent_request_id: Optional[str] = None,
        created_by: str = "ai",
    ) -> ApprovalRequest:
        spec = get_action_spec(action_type)
        if spec is None:
            raise ValueError(f"Unknown action type {action_type!r}")
        payload = dict(payload or {})
        missing = [name for name in spec.required_fields if not payload.get(name)]
        if missing:
            raise ValueError(f"{spec.label} is missing required fields: {', '.join(missing)}")

        request = ApprovalRequest(
            action_type=action_type,
            title=title or spec.label,
            summary=summary or spec.description,
            rationale=rationale,
            payload=payload,
            risk=spec.risk,
            cluster_id=cluster_id,
            session_id=session_id,
            source=source,
            created_by=created_by,
            question=question or (self._default_question(spec, payload) if spec.asks_question else None),
            parent_request_id=parent_request_id,
        )
        if spec.asks_question:
            request.follow_ups = self._normalize_follow_ups(payload, summary, follow_ups)
        if spec.execution == "informational":
            request.payload = self._enrich_informational(spec.action_type, request.payload)
            request.status = RequestStatus.INFORMATIONAL
        else:
            from .enrichment import enrich_request

            request = enrich_request(request)
        return self.store.put(request)

    def create_from_mcp_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        cluster_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ApprovalRequest:
        from .catalog import spec_for_mcp_tool

        spec = spec_for_mcp_tool(tool_name)
        if spec is None:
            raise ValueError(f"Tool {tool_name!r} is not gated through the approval queue")
        args = dict(arguments or {})
        title = args.get("title") or f"{spec.label}: {args.get('alert_id') or args.get('endpoint_id') or 'pending'}"
        summary = args.get("summary") or args.get("comment") or args.get("description") or spec.description
        rationale = (
            args.get("rationale")
            or args.get("comment")
            or args.get("description")
            or ""
        )
        payload = {
            key: value
            for key, value in args.items()
            if key not in {"summary", "rationale", "session_id", "cluster_id", "title"}
        }
        return self.create(
            action_type=spec.action_type,
            title=str(title),
            summary=str(summary),
            payload=payload,
            rationale=str(rationale),
            cluster_id=cluster_id,
            session_id=session_id or args.get("session_id"),
            source="mcp",
        )

    def ensure_enriched(self, request: ApprovalRequest) -> ApprovalRequest:
        """Backfill SIEM context on older/sparse pending requests and persist."""
        from .enrichment import enrich_request, needs_enrichment

        if request.status not in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
            return request
        if not needs_enrichment(request):
            return request
        enriched = enrich_request(request)
        return self.store.put(enriched)

    def deny(self, request_id: str, comment: Optional[str] = None, actor: str = "analyst") -> ApprovalRequest:
        request = self._require(request_id)
        if request.status == RequestStatus.INFORMATIONAL:
            raise ValueError("Informational requests have no action to deny")
        if request.status != RequestStatus.PENDING:
            raise ValueError("Only pending requests can be denied")
        request.status = RequestStatus.DENIED
        request.decision = Decision(action="deny", actor=actor, comment=comment)
        request.updated_at = datetime.now()
        return self.store.put(request)

    def approve(self, request_id: str, comment: Optional[str] = None, actor: str = "analyst") -> ApprovalRequest:
        request = self._require(request_id)
        if request.status == RequestStatus.INFORMATIONAL:
            raise ValueError("Informational requests have no action to approve")
        if request.status != RequestStatus.PENDING:
            raise ValueError("Only pending requests can be approved")
        spec = get_action_spec(request.action_type)
        if spec and spec.asks_question:
            raise ValueError("This request needs a yes/no answer, not a generic approve")
        request.decision = Decision(action="approve", actor=actor, comment=comment)
        request.updated_at = datetime.now()
        return self._execute(request)

    def answer(
        self,
        request_id: str,
        answer: str,
        comment: Optional[str] = None,
        actor: str = "analyst",
    ) -> ApprovalRequest:
        request = self._require(request_id)
        if request.status != RequestStatus.PENDING:
            raise ValueError("Only pending requests can be answered")
        spec = get_action_spec(request.action_type)
        if not spec or not spec.asks_question:
            raise ValueError("This request is not a question")
        normalized = str(answer).strip().lower()
        if normalized not in {"yes", "no"}:
            raise ValueError("Answer must be yes or no")
        follow = request.follow_ups.get(normalized)
        request.decision = Decision(
            action="answer",
            actor=actor,
            comment=comment,
            answer=normalized,
            follow_up_id=follow.id if follow else normalized,
        )
        request.updated_at = datetime.now()
        if follow is None:
            request.status = RequestStatus.EXECUTED
            request.execution_result = {
                "success": True,
                "message": f"Recorded answer '{normalized}' with no follow-up action.",
            }
            return self.store.put(request)

        child_spec = get_action_spec(follow.action_type)
        missing_follow = [
            name for name in (child_spec.required_fields if child_spec else ())
            if not follow.payload.get(name)
        ]
        if child_spec is None or missing_follow:
            request.status = RequestStatus.EXECUTED
            request.execution_result = {
                "success": True,
                "answer": normalized,
                "message": (
                    f"Recorded answer '{normalized}'. Follow-up "
                    f"{follow.action_type} was not run because required fields were missing."
                    if missing_follow
                    else f"Recorded answer '{normalized}'."
                ),
            }
            return self.store.put(request)

        child = self.create(
            action_type=follow.action_type,
            title=follow.label,
            summary=follow.summary or follow.label,
            payload=follow.payload,
            rationale=f"Follow-up after identity answer '{normalized}' on {request.id}",
            cluster_id=request.cluster_id,
            session_id=request.session_id,
            source="follow_up",
            parent_request_id=request.id,
            created_by=actor,
        )
        request.child_request_ids.append(child.id)
        auto_run = follow.action_type not in _CRITICAL_FOLLOW_UPS
        if auto_run:
            child.decision = Decision(
                action="approve",
                actor=actor,
                comment=comment or f"Auto-approved follow-up after identity answer '{normalized}'",
            )
            child = self._execute(child)
            request.status = child.status
            request.execution_result = {
                "success": child.status == RequestStatus.EXECUTED,
                "answer": normalized,
                "follow_up_id": child.id,
                "follow_up_action": follow.action_type,
                "follow_up_result": child.execution_result,
            }
            if child.error:
                request.error = child.error
        else:
            request.status = RequestStatus.EXECUTED
            request.execution_result = {
                "success": True,
                "answer": normalized,
                "follow_up_id": child.id,
                "follow_up_action": follow.action_type,
                "message": "Follow-up is high risk and was filed as a separate pending request.",
            }
        return self.store.put(request)

    def _execute(self, request: ApprovalRequest) -> ApprovalRequest:
        handler = get_handler(request.action_type)
        clients = resolve_clients(request.cluster_id)
        if clients.cluster_id and not request.cluster_id:
            request.cluster_id = clients.cluster_id
        try:
            result = handler.execute(request, clients)
        except Exception as exc:
            logger.exception("Failed to execute approval request %s (%s)", request.id, request.action_type)
            request.status = RequestStatus.FAILED
            request.error = str(exc)
            request.execution_result = {"success": False, "error": str(exc)}
            request.updated_at = datetime.now()
            return self.store.put(request)

        request.execution_result = result if isinstance(result, dict) else {"result": result}
        request.updated_at = datetime.now()
        if isinstance(result, dict) and result.get("needs_integration"):
            request.status = RequestStatus.AWAITING_INTEGRATION
            request.error = result.get("message")
        elif isinstance(result, dict) and result.get("success") is False:
            request.status = RequestStatus.FAILED
            request.error = str(result.get("error") or result.get("message") or "Execution failed")
        else:
            request.status = RequestStatus.EXECUTED
            request.error = None
        return self.store.put(request)

    def _require(self, request_id: str) -> ApprovalRequest:
        request = self.store.get(request_id)
        if request is None:
            raise KeyError(request_id)
        return request

    @staticmethod
    def _enrich_informational(action_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        from .lab_rules import enrich_fine_tune, enrich_visibility

        if action_type == "fine_tune":
            return enrich_fine_tune(payload)
        if action_type == "visibility":
            return enrich_visibility(payload)
        return payload

    @staticmethod
    def _default_question(spec, payload: Dict[str, Any]) -> str:
        user = payload.get("username") or "this user"
        activity = payload.get("activity") or "this activity"
        source = payload.get("source_ip") or payload.get("hostname")
        when = payload.get("timestamp")
        parts = [f"Was {activity} by {user} expected / actually you?"]
        if source:
            parts.append(f"Source: {source}.")
        if when:
            parts.append(f"When: {when}.")
        return " ".join(parts)

    @staticmethod
    def _normalize_follow_ups(
        payload: Dict[str, Any],
        summary: str,
        raw: Optional[Dict[str, Any]],
    ) -> Dict[str, FollowUpPlan]:
        defaults = {
            "yes": FollowUpPlan(
                id="acknowledge",
                label="Acknowledge — expected activity",
                action_type="close_alert",
                payload={
                    "alert_id": payload.get("alert_id"),
                    "reason": "benign_true_positive",
                    "comment": summary or "Analyst confirmed expected activity.",
                },
                summary="Close the related alert as a benign true positive.",
            ),
            "no": FollowUpPlan(
                id="escalate",
                label="Escalate — not the user",
                action_type="escalate",
                payload={
                    "alert_id": payload.get("alert_id"),
                    "title": f"Unauthorized activity: {payload.get('username') or 'user'}",
                    "description": summary or "Analyst said this was not them.",
                    "priority": "high",
                    "username": payload.get("username"),
                    "source_ip": payload.get("source_ip"),
                    "hostname": payload.get("hostname"),
                    "timestamp": payload.get("timestamp"),
                    "activity": payload.get("activity"),
                },
                summary="Tag the alert as true positive and open an Elastic Security case with the full alert.",
            ),
        }
        if not raw:
            return defaults

        normalized: Dict[str, FollowUpPlan] = {}
        for key, value in raw.items():
            answer_key = str(key).strip().lower()
            if answer_key not in {"yes", "no"} or not isinstance(value, dict):
                continue
            plan = FollowUpPlan.from_dict(value)
            if plan is None or not plan.action_type:
                continue
            if get_action_spec(plan.action_type) is None:
                continue
            normalized[answer_key] = plan
        return normalized or defaults
