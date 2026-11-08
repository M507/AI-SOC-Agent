"""Create, decide, and execute analyst approval requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ...core.logging import get_logger
from .actions import get_handler
from .catalog import (
    get_action_spec,
    list_action_specs,
    github_issue_link,
    matches_queue,
    wants_github_facet,
    queue_tab_for,
    ACTIONABLE_QUEUE_TABS,
    SOC_CATEGORIES,
    DETECTION_CATEGORIES,
    QUEUE_COUNT_KEYS,
)
from .clients import resolve_clients
from .dedupe import (
    ALERT_SCOPED_ACTIONS,
    ENDPOINT_SCOPED_ACTIONS,
    INFORMATIONAL_ACTIONS,
    EnqueueOutcome,
    find_open_alert_match,
    find_open_endpoint_match,
    find_open_flow_match,
    find_open_informational_match,
    find_related_requests as _find_related_requests,
    note_is_richer,
    related_alert_ids_of,
)
from .models import ApprovalRequest, Decision, FollowUpPlan, RequestStatus, is_archived
from .store import RequestStore

logger = get_logger("sami.approval_queue")

_CRITICAL_FOLLOW_UPS = {"isolate_endpoint", "kill_process", "disable_user", "reset_credentials"}
_OPEN_STATUSES = {RequestStatus.PENDING, RequestStatus.INFORMATIONAL, RequestStatus.AWAITING_INTEGRATION}
_IGNORE_GITHUB_COMMENT = "Manager decided to ignore this professionally."
_ENRICHMENT_RETRY_SECONDS = 900
_QUEUE_KEYS = QUEUE_COUNT_KEYS

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
        sync_github: bool = False,
        github: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        return self.list_bundle(
            status=status,
            cluster_id=cluster_id,
            queue=queue,
            sync_github=sync_github,
            github=github,
        )["items"]

    def list_bundle(
        self,
        status: Optional[str] = None,
        cluster_id: Optional[str] = None,
        queue: Optional[str] = None,
        sync_github: bool = False,
        github: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Local snapshot: tickets, badge counts, and generation. No GitHub or SIEM."""
        queue_key = (queue or "all").strip().lower()
        if sync_github:
            self.sync_github_closed(cluster_id=cluster_id)
        snapshot = self.store.snapshot()
        generation = self.store.generation
        clustered = snapshot
        if cluster_id:
            clustered = [item for item in snapshot if item.cluster_id == cluster_id]
        queued = [
            item for item in clustered if matches_queue(item.action_type, item.payload, queue_key)
        ]
        if wants_github_facet(github):
            queued = [item for item in queued if github_issue_link(item.payload)]
        items = self._apply_status(queued, status)
        items = sorted(items, key=lambda item: item.created_at, reverse=True)
        counts = self._counts_from(snapshot)
        queue_counts = self._queue_counts_from(snapshot)
        # Map legacy / alias queue keys onto a count bucket when needed.
        tab_aliases = {
            "soc": "approvals",
            "detection": "notes",
            "detections": "notes",
            "detection_engineering": "notes",
            "eng": "engineering",
        }
        tab_key = tab_aliases.get(queue_key, queue_key)
        if tab_key not in queue_counts:
            tab_key = "all"
        return {
            "items": items,
            "counts": counts,
            "tab_counts": queue_counts[tab_key],
            "queue_counts": queue_counts,
            "generation": generation,
            "queue": queue or "all",
            "github": bool(wants_github_facet(github)),
        }

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        request = self.store.get(request_id)
        if request is None:
            return None
        if request.status in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
            return self.ensure_enriched(request)
        return request

    def counts(self) -> Dict[str, int]:
        return self._counts_from(self.store.snapshot())

    def tab_counts(self, queue: Optional[str] = None) -> Dict[str, int]:
        """Open / archived / all counts for the active Requests top tab."""
        queue_counts = self._queue_counts_from(self.store.snapshot())
        key = (queue or "all").strip().lower()
        if key not in queue_counts:
            key = "all"
        return queue_counts[key]

    def summary(self) -> Dict[str, Any]:
        """Cheap badge payload for the Requests poll. Local files only."""
        snapshot = self.store.snapshot()
        return {
            "generation": self.store.generation,
            "counts": self._counts_from(snapshot),
            "queue_counts": self._queue_counts_from(snapshot),
        }

    @staticmethod
    def _apply_status(items: List[ApprovalRequest], status: Optional[str]) -> List[ApprovalRequest]:
        filter_key = (status or "all").strip().lower()
        if filter_key in {"pending", "open"}:
            return [
                item
                for item in items
                if not is_archived(item) and item.status in _OPEN_STATUSES
            ]
        if filter_key == "archived":
            return [item for item in items if is_archived(item)]
        if filter_key == "all":
            return list(items)
        try:
            parsed = RequestStatus(filter_key)
        except ValueError as exc:
            raise ValueError(f"Unknown request filter {status!r}") from exc
        return [item for item in items if item.status == parsed]

    @staticmethod
    def _counts_from(items: List[ApprovalRequest]) -> Dict[str, int]:
        open_items = [item for item in items if not is_archived(item) and item.status in _OPEN_STATUSES]
        archived_count = sum(1 for item in items if is_archived(item))
        informational = sum(1 for item in open_items if item.status == RequestStatus.INFORMATIONAL)
        awaiting = sum(1 for item in open_items if item.status == RequestStatus.AWAITING_INTEGRATION)
        actionable = 0
        approvals_open = 0
        notes_open = 0
        detection_open = 0
        engineering_open = 0
        soc_open = 0
        closures_open = 0
        alert_notes_open = 0
        questions_open = 0
        response_open = 0
        fine_tune_open = 0
        visibility_open = 0
        runbooks_open = 0
        for item in open_items:
            spec = get_action_spec(item.action_type)
            category = spec.category if spec else ""
            tab = queue_tab_for(item.action_type)
            is_note = category in DETECTION_CATEGORIES
            # Nav badge: pending Closures + Questions + Response only.
            if item.status == RequestStatus.PENDING and tab in ACTIONABLE_QUEUE_TABS:
                actionable += 1
            if tab == "closures":
                closures_open += 1
            elif tab == "alert_notes":
                alert_notes_open += 1
            elif tab == "questions":
                questions_open += 1
            elif tab == "response":
                response_open += 1
            elif tab == "fine_tune":
                fine_tune_open += 1
            elif tab == "visibility":
                visibility_open += 1
            elif tab == "runbooks":
                runbooks_open += 1
            if is_note:
                notes_open += 1
                detection_open += 1
            else:
                approvals_open += 1
                if category in SOC_CATEGORIES:
                    soc_open += 1
            if github_issue_link(item.payload):
                engineering_open += 1
        return {
            "pending": len(open_items),
            "open": len(open_items),
            "archived": archived_count,
            "informational": informational,
            "awaiting": awaiting,
            "actionable": actionable,
            "approvals_open": approvals_open,
            "notes_open": notes_open,
            "soc_open": soc_open,
            "detection_open": detection_open,
            "engineering_open": engineering_open,
            "closures_open": closures_open,
            "alert_notes_open": alert_notes_open,
            "questions_open": questions_open,
            "response_open": response_open,
            "fine_tune_open": fine_tune_open,
            "visibility_open": visibility_open,
            "runbooks_open": runbooks_open,
            "all": len(items),
        }

    @staticmethod
    def _queue_counts_from(items: List[ApprovalRequest]) -> Dict[str, Dict[str, int]]:
        result: Dict[str, Dict[str, int]] = {}
        for queue_key in _QUEUE_KEYS:
            matched = [
                item for item in items if matches_queue(item.action_type, item.payload, queue_key)
            ]
            open_items = [
                item for item in matched if not is_archived(item) and item.status in _OPEN_STATUSES
            ]
            result[queue_key] = {
                "open": len(open_items),
                "archived": sum(1 for item in matched if is_archived(item)),
                "all": len(matched),
            }
        return result

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
        *,
        dedupe: bool = True,
    ) -> ApprovalRequest:
        outcome = self.enqueue(
            action_type=action_type,
            title=title,
            summary=summary,
            payload=payload,
            rationale=rationale,
            cluster_id=cluster_id,
            session_id=session_id,
            source=source,
            question=question,
            follow_ups=follow_ups,
            parent_request_id=parent_request_id,
            created_by=created_by,
            dedupe=dedupe,
        )
        return outcome.request

    def enqueue(
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
        *,
        dedupe: bool = True,
    ) -> EnqueueOutcome:
        """Create a request, or reuse/update an open IR-equivalent match."""
        spec = get_action_spec(action_type)
        if spec is None:
            raise ValueError(f"Unknown action type {action_type!r}")
        payload = dict(payload or {})
        missing = [name for name in spec.required_fields if not payload.get(name)]
        if missing:
            raise ValueError(f"{spec.label} is missing required fields: {', '.join(missing)}")

        if dedupe:
            reused = self._reuse_open_request(
                action_type=action_type,
                title=title,
                summary=summary,
                payload=payload,
                rationale=rationale,
                cluster_id=cluster_id,
                session_id=session_id,
            )
            if reused is not None:
                return reused

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
        return EnqueueOutcome(request=self.store.put(request), outcome="created")

    def _reuse_open_request(
        self,
        *,
        action_type: str,
        title: str,
        summary: str,
        payload: Dict[str, Any],
        rationale: str,
        cluster_id: Optional[str],
        session_id: Optional[str],
    ) -> Optional[EnqueueOutcome]:
        snapshot = self.store.snapshot()
        existing: Optional[ApprovalRequest] = None
        if action_type in ALERT_SCOPED_ACTIONS:
            alert_id = str(payload.get("alert_id") or "").strip()
            if alert_id:
                existing = find_open_alert_match(
                    snapshot,
                    action_type=action_type,
                    alert_id=alert_id,
                    cluster_id=cluster_id,
                )
            if existing is None:
                existing = find_open_flow_match(
                    snapshot,
                    action_type=action_type,
                    payload=payload,
                    cluster_id=cluster_id,
                )
        elif action_type in INFORMATIONAL_ACTIONS:
            existing = find_open_informational_match(
                snapshot,
                action_type=action_type,
                payload=payload,
                title=title,
                summary=summary,
                cluster_id=cluster_id,
            )
        elif action_type in ENDPOINT_SCOPED_ACTIONS:
            existing = find_open_endpoint_match(
                snapshot,
                action_type=action_type,
                payload=payload,
                cluster_id=cluster_id,
            )
        if existing is None:
            return None

        if action_type in ALERT_SCOPED_ACTIONS:
            existing = self._merge_related_alert_ids(existing, payload)

        if action_type == "add_alert_note":
            new_note = str(payload.get("note") or summary or "").strip()
            old_note = str(
                (existing.payload or {}).get("note") or existing.summary or ""
            ).strip()
            if note_is_richer(old_note, new_note):
                existing.payload = dict(existing.payload or {})
                existing.payload["note"] = new_note
                if payload.get("rule_name"):
                    existing.payload.setdefault("rule_name", payload.get("rule_name"))
                existing.summary = summary or new_note or existing.summary
                if rationale:
                    existing.rationale = rationale
                if session_id and not existing.session_id:
                    existing.session_id = session_id
                existing.updated_at = datetime.now()
                from .enrichment import enrich_request

                existing = enrich_request(existing, force=True)
                return EnqueueOutcome(request=self.store.put(existing), outcome="updated")
            if session_id and not existing.session_id:
                existing.session_id = session_id
                existing.updated_at = datetime.now()
                return EnqueueOutcome(request=self.store.put(existing), outcome="deduplicated")
            # related_alert_ids may have changed even when note text did not
            existing.updated_at = datetime.now()
            return EnqueueOutcome(request=self.store.put(existing), outcome="deduplicated")

        if action_type == "close_alert":
            changed = False
            existing.payload = dict(existing.payload or {})
            for key in ("reason", "comment"):
                value = payload.get(key)
                if value and value != existing.payload.get(key):
                    existing.payload[key] = value
                    changed = True
            if rationale and rationale != existing.rationale:
                existing.rationale = rationale
                changed = True
            if summary and summary != existing.summary:
                existing.summary = summary
                changed = True
            if session_id and not existing.session_id:
                existing.session_id = session_id
                changed = True
            # Always persist after related_alert_ids merge
            existing.updated_at = datetime.now()
            return EnqueueOutcome(
                request=self.store.put(existing),
                outcome="updated" if changed else "deduplicated",
            )

        if session_id and not existing.session_id:
            existing.session_id = session_id
            existing.updated_at = datetime.now()
            return EnqueueOutcome(request=self.store.put(existing), outcome="deduplicated")
        return EnqueueOutcome(request=existing, outcome="deduplicated")

    @staticmethod
    def _merge_related_alert_ids(
        existing: ApprovalRequest,
        payload: Dict[str, Any],
    ) -> ApprovalRequest:
        """Keep one ticket but remember every SIEM alert_id that folded into it."""
        existing.payload = dict(existing.payload or {})
        ids = related_alert_ids_of(existing)
        for key in ("alert_id", "alertId"):
            raw = payload.get(key)
            if raw not in (None, ""):
                text = str(raw).strip()
                if text and text not in ids:
                    ids.append(text)
        extra = payload.get("related_alert_ids") or payload.get("alert_ids") or []
        if isinstance(extra, str):
            extra = [part.strip() for part in extra.split(",") if part.strip()]
        if isinstance(extra, list):
            for raw in extra:
                text = str(raw or "").strip()
                if text and text not in ids:
                    ids.append(text)
        if ids:
            existing.payload["alert_id"] = ids[0]
            if len(ids) > 1:
                existing.payload["related_alert_ids"] = ids
        return existing

    def find_related_requests(
        self,
        *,
        alert_id: Optional[str] = None,
        action_type: Optional[str] = None,
        action_types: Optional[List[str]] = None,
        rule_id: Optional[str] = None,
        rule_name: Optional[str] = None,
        query: Optional[str] = None,
        cluster_id: Optional[str] = None,
        open_only: bool = True,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        types = list(action_types or [])
        if action_type:
            types.append(action_type)
        return _find_related_requests(
            self.store.snapshot(),
            alert_id=alert_id,
            action_types=types or None,
            rule_id=rule_id,
            rule_name=rule_name,
            query=query,
            cluster_id=cluster_id,
            open_only=open_only,
            limit=limit,
        )

    def create_from_mcp_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        cluster_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ApprovalRequest:
        return self.enqueue_from_mcp_tool(
            tool_name,
            arguments,
            cluster_id=cluster_id,
            session_id=session_id,
        ).request

    def enqueue_from_mcp_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        cluster_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> EnqueueOutcome:
        from .catalog import spec_for_mcp_tool

        spec = spec_for_mcp_tool(tool_name)
        if spec is None:
            raise ValueError(f"Tool {tool_name!r} is not gated through the approval queue")
        args = dict(arguments or {})
        title = args.get("title") or f"{spec.label}: {args.get('alert_id') or args.get('endpoint_id') or 'pending'}"
        summary = (
            args.get("summary")
            or args.get("comment")
            or args.get("note")
            or args.get("description")
            or spec.description
        )
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
        return self.enqueue(
            action_type=spec.action_type,
            title=str(title),
            summary=str(summary),
            payload=payload,
            rationale=str(rationale),
            cluster_id=cluster_id,
            session_id=session_id or args.get("session_id"),
            source="mcp",
        )

    def ensure_enriched(self, request: ApprovalRequest, *, force: bool = False) -> ApprovalRequest:
        """Backfill SIEM context on older/sparse pending requests and persist."""
        from .enrichment import enrich_request, needs_enrichment

        if request.status not in {RequestStatus.PENDING, RequestStatus.INFORMATIONAL}:
            return request
        if not needs_enrichment(request):
            return request
        if not force and request.enrichment_attempted_at:
            elapsed = (datetime.now() - request.enrichment_attempted_at).total_seconds()
            if elapsed < _ENRICHMENT_RETRY_SECONDS:
                return request
        enriched = enrich_request(request)
        if needs_enrichment(enriched):
            enriched.enrichment_attempted_at = datetime.now()
        else:
            enriched.enrichment_attempted_at = None
        enriched.updated_at = datetime.now()
        return self.store.put(enriched)

    def enrich_open(self, cluster_id: Optional[str] = None) -> Dict[str, Any]:
        """One-pass SIEM backfill for open tickets that still need a snapshot."""
        from .enrichment import needs_enrichment

        checked = 0
        enriched = 0
        failed = 0
        for item in self.store.snapshot():
            if cluster_id and item.cluster_id != cluster_id:
                continue
            if is_archived(item) or item.status not in {
                RequestStatus.PENDING,
                RequestStatus.INFORMATIONAL,
            }:
                continue
            if not needs_enrichment(item):
                continue
            checked += 1
            updated = self.ensure_enriched(item)
            if needs_enrichment(updated):
                failed += 1
            else:
                enriched += 1
        return {
            "enrichment_checked": checked,
            "enriched": enriched,
            "enrichment_failed": failed,
        }

    def attach_engineering(self, request_id: str, engineering: Dict[str, Any]) -> ApprovalRequest:
        """Persist a GitHub (or other ENG) mirror onto the request payload."""
        request = self._require(request_id)
        payload = dict(request.payload or {})
        payload["engineering"] = engineering
        request.payload = payload
        request.updated_at = datetime.now()
        return self.store.put(request)

    def sync_external_closed(self, cluster_id: Optional[str] = None) -> Dict[str, Any]:
        """Archive open notes whose linked engineering ticket is already closed."""
        return self.sync_github_closed(cluster_id=cluster_id)

    def refresh_external(self, cluster_id: Optional[str] = None) -> Dict[str, Any]:
        """GitHub close-sync plus one SIEM backfill pass. Used when Requests opens or Refresh is clicked."""
        github = self.sync_github_closed(cluster_id=cluster_id)
        siem = self.enrich_open(cluster_id=cluster_id)
        return {**github, **siem}

    def sync_github_closed(self, cluster_id: Optional[str] = None) -> Dict[str, Any]:
        """Archive open mirrored notes whose GitHub issue is already closed."""
        checked = 0
        closed = 0
        errors = 0
        for item in list(self.store.list(cluster_id=cluster_id)):
            if item.status != RequestStatus.INFORMATIONAL or is_archived(item):
                continue
            link = github_issue_link(item.payload)
            if not link:
                continue
            provider = str(link.get("provider") or "github").lower()
            if provider not in {"github", ""}:
                continue
            checked += 1
            try:
                issue = self._github_get_issue(item, str(link["number"]))
            except Exception as exc:
                errors += 1
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
                errors += 1
                logger.warning("Could not archive request %s after GitHub close: %s", item.id, exc)
        return {
            "checked": checked,
            "closed": closed,
            "errors": errors,
            "providers": ["github"],
        }

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
            if normalized == "approve" and request.status in {
                RequestStatus.EXECUTED,
                RequestStatus.FAILED,
                RequestStatus.DENIED,
                RequestStatus.AWAITING_INTEGRATION,
            }:
                skipped += 1
                results.append(
                    {
                        "id": request_id,
                        "success": True,
                        "skipped": True,
                        "error": "Already settled",
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

    @staticmethod
    def _request_alert_ids(request: ApprovalRequest) -> set:
        """Alert ids on a request: top-level payload and the enriched alert snapshot."""
        ids = set()
        payload = request.payload or {}
        for raw in (payload.get("alert_id"), payload.get("alertId")):
            text = str(raw or "").strip()
            if text:
                ids.add(text)
        alert = payload.get("alert")
        if isinstance(alert, dict):
            for raw in (alert.get("id"), alert.get("alert_id"), alert.get("alertId")):
                text = str(raw or "").strip()
                if text:
                    ids.add(text)
        return ids

    def _pending_notes_for_alert(self, close_request: ApprovalRequest) -> List[ApprovalRequest]:
        """Pending add-note requests for the same alert (and cluster, when both are set)."""
        wanted = self._request_alert_ids(close_request)
        if not wanted:
            return []
        close_cluster = close_request.cluster_id or None
        matches: List[ApprovalRequest] = []
        for item in self.store.list():
            if item.id == close_request.id:
                continue
            if item.action_type != "add_alert_note" or item.status != RequestStatus.PENDING:
                continue
            if not (self._request_alert_ids(item) & wanted):
                continue
            note_cluster = item.cluster_id or None
            if close_cluster and note_cluster and close_cluster != note_cluster:
                continue
            matches.append(item)
        return matches

    def _approve_associated_notes(self, close_request: ApprovalRequest) -> List[Dict[str, Any]]:
        """Approve pending notes for this alert so a close cannot land without them."""
        notes = self._pending_notes_for_alert(close_request)
        if not notes:
            return []
        alert_id = next(iter(self._request_alert_ids(close_request)), "")
        actor = "analyst"
        comment = f"Approved with close of alert {alert_id}" if alert_id else "Approved with close alert"
        if close_request.decision:
            actor = close_request.decision.actor or actor
            if close_request.decision.comment:
                comment = close_request.decision.comment
        results: List[Dict[str, Any]] = []
        for note in notes:
            if close_request.cluster_id and not note.cluster_id:
                note.cluster_id = close_request.cluster_id
            payload = dict(note.payload or {})
            if not payload.get("alert_id"):
                overlap = self._request_alert_ids(note) & self._request_alert_ids(close_request)
                fill = next(iter(overlap), None) or alert_id
                if fill:
                    payload["alert_id"] = fill
                    note.payload = payload
            note.decision = Decision(action="approve", actor=actor, comment=comment)
            note.updated_at = datetime.now()
            updated = self._execute(note)
            if updated.id not in close_request.child_request_ids:
                close_request.child_request_ids.append(updated.id)
            results.append(
                {
                    "id": updated.id,
                    "status": updated.status.value,
                    "success": updated.status == RequestStatus.EXECUTED,
                    "error": updated.error,
                    "note": (updated.payload or {}).get("note"),
                }
            )
        return results

    def _execute(self, request: ApprovalRequest) -> ApprovalRequest:
        associated_notes: List[Dict[str, Any]] = []
        if request.action_type == "close_alert":
            associated_notes = self._approve_associated_notes(request)
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
            if associated_notes:
                request.execution_result["associated_notes"] = associated_notes
            self._mark_archived(request)
            return self.store.put(request)

        request.execution_result = result if isinstance(result, dict) else {"result": result}
        if associated_notes:
            request.execution_result["associated_notes"] = associated_notes
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
