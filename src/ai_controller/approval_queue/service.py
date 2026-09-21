"""Create, decide, and execute analyst approval requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ...core.logging import get_logger
from .actions import get_handler
from .catalog import get_action_spec, list_action_specs, github_issue_link, matches_queue, SOC_CATEGORIES, DETECTION_CATEGORIES
from .clients import resolve_clients
from .models import ApprovalRequest, Decision, FollowUpPlan, RequestStatus, is_archived
from .store import RequestStore

logger = get_logger("sami.approval_queue")

_CRITICAL_FOLLOW_UPS = {"isolate_endpoint", "kill_process", "disable_user", "reset_credentials"}
_OPEN_STATUSES = {RequestStatus.PENDING, RequestStatus.INFORMATIONAL, RequestStatus.AWAITING_INTEGRATION}
_IGNORE_GITHUB_COMMENT = "Manager decided to ignore this professionally."

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
        queue: Optional[str] = None,
        sync_github: bool = True,
    ) -> List[ApprovalRequest]:
        queue_key = (queue or "all").strip().lower()
        filter_key = (status or "all").strip().lower()
        if sync_github and filter_key in {"open", "pending", "all", "informational"} and queue_key in {
            "all",
            "engineering",
            "eng",
            "detection",
            "detections",
            "detection_engineering",
        }:
            self.sync_github_closed(cluster_id=cluster_id)
        items = self.store.list(cluster_id=cluster_id)
        items = [item for item in items if matches_queue(item.action_type, item.payload, queue_key)]
        if filter_key in {"pending", "open"}:
            items = [
                item
                for item in items
                if not is_archived(item) and item.status in _OPEN_STATUSES
            ]
            items = [self.ensure_enriched(item) for item in items]
        elif filter_key == "archived":
            items = [item for item in items if is_archived(item)]
        elif filter_key == "all":
            items = [
                self.ensure_enriched(item)
                if item.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}
                else item
                for item in items
            ]
        else:
            try:
                parsed = RequestStatus(filter_key)
            except ValueError as exc:
                raise ValueError(f"Unknown request filter {status!r}") from exc
            items = [item for item in items if item.status == parsed]
            if parsed in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
                items = [self.ensure_enriched(item) for item in items]
        return sorted(items, key=lambda item: item.created_at, reverse=True)

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        request = self.store.get(request_id)
        if request is None:
            return None
        if request.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
            return self.ensure_enriched(request)
        return request

    def counts(self) -> Dict[str, int]:
        items = self.store.list()
        open_items = [item for item in items if not is_archived(item) and item.status in _OPEN_STATUSES]
        archived_count = sum(1 for item in items if is_archived(item))
        informational = sum(1 for item in open_items if item.status == RequestStatus.INFORMATIONAL)
        awaiting = sum(1 for item in open_items if item.status == RequestStatus.AWAITING_INTEGRATION)
        actionable = 0
        detection_open = 0
        engineering_open = 0
        soc_open = 0
        for item in open_items:
            spec = get_action_spec(item.action_type)
            category = spec.category if spec else ""
            if item.status == RequestStatus.PENDING and category in SOC_CATEGORIES:
                actionable += 1
            if category in SOC_CATEGORIES:
                soc_open += 1
            if category in DETECTION_CATEGORIES:
                detection_open += 1
            if github_issue_link(item.payload):
                engineering_open += 1
        return {
            "pending": len(open_items),
            "open": len(open_items),
            "archived": archived_count,
            "informational": informational,
            "awaiting": awaiting,
            "actionable": actionable,
            "soc_open": soc_open,
            "detection_open": detection_open,
            "engineering_open": engineering_open,
            "all": len(items),
        }

    def tab_counts(self, queue: Optional[str] = None) -> Dict[str, int]:
        """Open / archived / all counts for the active Requests top tab."""
        items = [
            item
            for item in self.store.list()
            if matches_queue(item.action_type, item.payload, queue)
        ]
        open_items = [
            item for item in items if not is_archived(item) and item.status in _OPEN_STATUSES
        ]
        return {
            "open": len(open_items),
            "archived": sum(1 for item in items if is_archived(item)),
            "all": len(items),
        }

    @staticmethod
    def _mark_archived(request: ApprovalRequest) -> ApprovalRequest:
        request.archived = True
        request.archived_at = request.archived_at or datetime.now()
        request.updated_at = datetime.now()
        return request

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
        # Keep title/description in payload — many ActionSpecs require them, and
        # informational enrichers (fine_tune / visibility / runbook_gap) read them.
        payload = {
            key: value
            for key, value in args.items()
            if key not in {"summary", "rationale", "session_id", "cluster_id"}
        }
        if "title" not in payload and title:
            payload["title"] = title
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

    def attach_engineering(self, request_id: str, engineering: Dict[str, Any]) -> ApprovalRequest:
        """Persist a GitHub (or other ENG) mirror onto the request payload."""
        request = self._require(request_id)
        payload = dict(request.payload or {})
        payload["engineering"] = engineering
        request.payload = payload
        request.updated_at = datetime.now()
        return self.store.put(request)

    def sync_github_closed(self, cluster_id: Optional[str] = None) -> int:
        """Archive open mirrored notes whose GitHub issue is already closed."""
        closed = 0
        for item in list(self.store.list(cluster_id=cluster_id)):
            if item.status != RequestStatus.INFORMATIONAL or is_archived(item):
                continue
            link = github_issue_link(item.payload)
            if not link:
                continue
            try:
                issue = self._github_get_issue(item, str(link["number"]))
            except Exception as exc:
                logger.warning("GitHub sync skipped for request %s: %s", item.id, exc)
                continue
            state = str((issue or {}).get("state") or "").lower()
            if state != "closed":
                continue
            number = link.get("number")
            try:
                self.acknowledge(
                    item.id,
                    comment=f"Closed on GitHub #{number}",
                    actor="github",
                )
                closed += 1
            except Exception as exc:
                logger.warning("Could not archive request %s after GitHub close: %s", item.id, exc)
        return closed

    def ignore(
        self,
        request_id: str,
        comment: Optional[str] = None,
        actor: str = "analyst",
    ) -> ApprovalRequest:
        """Archive an informational note and close the linked GitHub issue."""
        request = self._require(request_id)
        if request.status != RequestStatus.INFORMATIONAL:
            raise ValueError("Only informational requests can be ignored")
        extra = (comment or "").strip()
        github_body = _IGNORE_GITHUB_COMMENT
        if extra:
            github_body = f"{github_body}\n\n{extra}"
        github_result: Dict[str, Any] = {"attempted": False}
        link = github_issue_link(request.payload)
        if link:
            github_result["attempted"] = True
            try:
                issue = self._github_close_issue(request, str(link["number"]), github_body)
                github_result["success"] = True
                github_result["issue"] = {
                    "number": (issue or {}).get("number") or link.get("number"),
                    "state": (issue or {}).get("state") or "closed",
                    "url": (issue or {}).get("html_url") or link.get("url"),
                }
            except Exception as exc:
                logger.warning("Ignore archived %s locally but GitHub close failed: %s", request_id, exc)
                github_result["success"] = False
                github_result["error"] = str(exc)
        if github_result.get("success") and link:
            payload = dict(request.payload or {})
            engineering = dict(payload.get("engineering") or {})
            issue = dict(engineering.get("issue") or {})
            issue["number"] = github_result.get("issue", {}).get("number") or link.get("number")
            issue["url"] = github_result.get("issue", {}).get("url") or link.get("url")
            issue["state"] = "closed"
            engineering["issue"] = issue
            engineering["provider"] = engineering.get("provider") or link.get("provider") or "github"
            engineering["repository"] = engineering.get("repository") or link.get("repository")
            payload["engineering"] = engineering
            request.payload = payload
        request.status = RequestStatus.ACKNOWLEDGED
        request.decision = Decision(action="ignore", actor=actor, comment=comment or _IGNORE_GITHUB_COMMENT)
        request.execution_result = {
            "success": True,
            "informational": True,
            "archived": True,
            "ignored": True,
            "message": "Ignored. Linked GitHub issue was closed." if github_result.get("success") else (
                "Ignored locally. GitHub issue was not closed." if github_result.get("attempted") else "Ignored. No GitHub issue was linked."
            ),
            "github": github_result,
        }
        if github_result.get("error"):
            request.error = f"GitHub close failed: {github_result['error']}"
        else:
            request.error = None
        self._mark_archived(request)
        return self.store.put(request)

    @staticmethod
    def _github_client_for(request: ApprovalRequest):
        from ...integrations.eng.github.github_client import GitHubClient

        bundle = resolve_clients(request.cluster_id)
        eng = bundle.eng
        if not isinstance(eng, GitHubClient):
            raise RuntimeError("No GitHub engineering client is configured")
        return eng

    def _github_get_issue(self, request: ApprovalRequest, number: str) -> Dict[str, Any]:
        return self._github_client_for(request).get_issue(number)

    def _github_close_issue(self, request: ApprovalRequest, number: str, comment: str) -> Dict[str, Any]:
        return self._github_client_for(request).close_issue(number, comment=comment)

    def deny(self, request_id: str, comment: Optional[str] = None, actor: str = "analyst") -> ApprovalRequest:
        request = self._require(request_id)
        if request.status == RequestStatus.INFORMATIONAL:
            raise ValueError("Informational requests have no action to deny — mark them Done instead")
        if request.status != RequestStatus.PENDING:
            raise ValueError("Only pending requests can be denied")
        request.status = RequestStatus.DENIED
        request.decision = Decision(action="deny", actor=actor, comment=comment)
        self._mark_archived(request)
        return self.store.put(request)

    def acknowledge(
        self,
        request_id: str,
        comment: Optional[str] = None,
        actor: str = "analyst",
    ) -> ApprovalRequest:
        """Mark an informational request as reviewed (Done). Archives it out of Open."""
        request = self._require(request_id)
        if request.status != RequestStatus.INFORMATIONAL:
            raise ValueError("Only informational requests can be marked Done")
        request.status = RequestStatus.ACKNOWLEDGED
        request.decision = Decision(action="acknowledge", actor=actor, comment=comment)
        request.execution_result = {
            "success": True,
            "informational": True,
            "archived": True,
            "message": "Marked as reviewed and archived. No side effects.",
        }
        self._mark_archived(request)
        return self.store.put(request)

    def approve(self, request_id: str, comment: Optional[str] = None, actor: str = "analyst") -> ApprovalRequest:
        request = self._require(request_id)
        if request.status == RequestStatus.INFORMATIONAL:
            raise ValueError("Informational requests have no action to approve — mark them Done instead")
        if request.status != RequestStatus.PENDING:
            raise ValueError("Only pending requests can be approved")
        spec = get_action_spec(request.action_type)
        if spec and spec.asks_question:
            raise ValueError("This request needs a yes/no answer, not a generic approve")
        request.decision = Decision(action="approve", actor=actor, comment=comment)
        request.updated_at = datetime.now()
        return self._execute(request)

    def bulk(
        self,
        action: str,
        request_ids: List[str],
        comment: Optional[str] = None,
        actor: str = "analyst",
    ) -> Dict[str, Any]:
        """Approve, deny, or acknowledge many requests. Skips items that cannot take that action."""
        normalized = str(action or "").strip().lower()
        if normalized in {"done", "ack"}:
            normalized = "acknowledge"
        if normalized not in {"approve", "deny", "acknowledge", "ignore"}:
            raise ValueError("Bulk action must be approve, deny, acknowledge, or ignore")
        results: List[Dict[str, Any]] = []
        succeeded = 0
        skipped = 0
        failed = 0
        for request_id in request_ids:
            try:
                request = self._require(request_id)
            except KeyError:
                failed += 1
                results.append({"id": request_id, "success": False, "error": "not found"})
                continue
            spec = get_action_spec(request.action_type)
            informational = request.status == RequestStatus.INFORMATIONAL or (
                spec is not None and spec.execution == "informational" and request.status == RequestStatus.INFORMATIONAL
            )
            if normalized == "acknowledge":
                if request.status != RequestStatus.INFORMATIONAL:
                    skipped += 1
                    results.append(
                        {
                            "id": request_id,
                            "success": False,
                            "skipped": True,
                            "error": "Only informational requests can be marked Done",
                            "status": request.status.value,
                        }
                    )
                    continue
            elif normalized == "ignore":
                if request.status != RequestStatus.INFORMATIONAL:
                    skipped += 1
                    results.append(
                        {
                            "id": request_id,
                            "success": False,
                            "skipped": True,
                            "error": "Only informational requests can be ignored",
                            "status": request.status.value,
                        }
                    )
                    continue
            elif informational:
                skipped += 1
                results.append(
                    {
                        "id": request_id,
                        "success": False,
                        "skipped": True,
                        "error": "Informational requests have no approve/deny action — mark them Done instead",
                        "status": request.status.value,
                    }
                )
                continue
            if normalized == "approve" and spec and spec.asks_question:
                skipped += 1
                results.append(
                    {
                        "id": request_id,
                        "success": False,
                        "skipped": True,
                        "error": "Needs an individual yes/no answer",
                        "status": request.status.value,
                    }
                )
                continue
            try:
                if normalized == "approve":
                    updated = self.approve(request_id, comment=comment, actor=actor)
                elif normalized == "deny":
                    updated = self.deny(request_id, comment=comment, actor=actor)
                elif normalized == "ignore":
                    updated = self.ignore(request_id, comment=comment, actor=actor)
                else:
                    updated = self.acknowledge(request_id, comment=comment, actor=actor)
                succeeded += 1
                results.append(
                    {
                        "id": request_id,
                        "success": True,
                        "status": updated.status.value,
                        "error": updated.error,
                    }
                )
            except Exception as exc:
                failed += 1
                results.append({"id": request_id, "success": False, "error": str(exc)})
        return {
            "action": normalized,
            "succeeded": succeeded,
            "skipped": skipped,
            "failed": failed,
            "results": results,
        }

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
            self._mark_archived(request)
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
            self._mark_archived(request)
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
            if request.status == RequestStatus.AWAITING_INTEGRATION:
                request.archived = False
            else:
                self._mark_archived(request)
        else:
            request.status = RequestStatus.EXECUTED
            request.execution_result = {
                "success": True,
                "answer": normalized,
                "follow_up_id": child.id,
                "follow_up_action": follow.action_type,
                "message": "Follow-up is high risk and was filed as a separate pending request.",
            }
            self._mark_archived(request)
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
            self._mark_archived(request)
            return self.store.put(request)

        request.execution_result = result if isinstance(result, dict) else {"result": result}
        request.updated_at = datetime.now()
        if isinstance(result, dict) and result.get("needs_integration"):
            request.status = RequestStatus.AWAITING_INTEGRATION
            request.error = result.get("message")
            request.archived = False
        elif isinstance(result, dict) and result.get("success") is False:
            request.status = RequestStatus.FAILED
            request.error = str(result.get("error") or result.get("message") or "Execution failed")
            self._mark_archived(request)
        else:
            request.status = RequestStatus.EXECUTED
            request.error = None
            self._mark_archived(request)
        return self.store.put(request)

    def _require(self, request_id: str) -> ApprovalRequest:
        request = self.store.get(request_id)
        if request is None:
            raise KeyError(request_id)
        return request

    @staticmethod
    def _enrich_informational(action_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        from .lab_rules import enrich_fine_tune, enrich_visibility
        from .runbook_gaps import enrich_runbook_gap

        if action_type == "fine_tune":
            return enrich_fine_tune(payload)
        if action_type == "visibility":
            return enrich_visibility(payload)
        if action_type == "runbook_gap":
            return enrich_runbook_gap(payload)
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
