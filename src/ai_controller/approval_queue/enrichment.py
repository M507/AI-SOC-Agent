"""Enrich approval requests with SIEM/alert context for human review."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ...core.logging import get_logger
from .catalog import get_action_spec
from .clients import resolve_clients
from .models import ApprovalRequest

logger = get_logger("sami.approval_queue.enrichment")

_GENERIC_SUMMARIES = {
    "close a siem alert, typically as a false positive or benign true positive.",
}
_MAX_EVENTS = 8
_MAX_EVENT_CHARS = 600
_MAX_DESCRIPTION = 4000
_MAX_COMMENT_CHARS = 2000


def enrich_request(request: ApprovalRequest, *, force: bool = False) -> ApprovalRequest:
    """
    Attach everything useful for an analyst decision.

    Pulls the SIEM alert (when alert_id is present), fills empty/generic
    title/summary/rationale, and copies common entity fields into the payload.
    Safe to call repeatedly; skips work when already enriched unless force=True.
    """
    payload = dict(request.payload or {})
    already = bool(payload.get("alert")) and not force
    alert_id = payload.get("alert_id")
    alert: Optional[Dict[str, Any]] = payload.get("alert") if isinstance(payload.get("alert"), dict) else None

    if alert_id and (force or not alert):
        fetched = _fetch_alert(str(alert_id), request.cluster_id)
        if fetched:
            alert = _compact_alert(fetched)
            payload["alert"] = alert
            _copy_alert_fields_into_payload(payload, alert)
            already = False

    if already and not force:
        request.payload = payload
        return request

    spec = get_action_spec(request.action_type)
    catalog_description = (spec.description if spec else "") or ""
    title, summary, rationale = _humanize_text(
        action_type=request.action_type,
        title=request.title,
        summary=request.summary,
        rationale=request.rationale,
        payload=payload,
        alert=alert,
        catalog_description=catalog_description,
    )
    request.title = title
    request.summary = summary
    request.rationale = rationale
    if spec and spec.asks_question and not request.question:
        request.question = _default_identity_question(payload)
    request.payload = payload
    return request


def needs_enrichment(request: ApprovalRequest) -> bool:
    payload = request.payload or {}
    if payload.get("alert_id") and not payload.get("alert"):
        return True
    summary = (request.summary or "").strip().lower()
    if summary in _GENERIC_SUMMARIES:
        return True
    if not (request.rationale or "").strip() and payload.get("alert_id"):
        return True
    return False


def _fetch_alert(alert_id: str, cluster_id: Optional[str]) -> Optional[Dict[str, Any]]:
    try:
        clients = resolve_clients(cluster_id)
        if clients.siem is None or not hasattr(clients.siem, "get_security_alert_by_id"):
            return None
        return clients.siem.get_security_alert_by_id(alert_id, include_detections=True)
    except Exception as exc:
        logger.warning("Could not enrich approval request with alert %s: %s", alert_id, exc)
        return None


def _compact_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Keep a review-friendly snapshot (not the full raw document)."""
    entities = alert.get("related_entities") or []
    if not isinstance(entities, list):
        entities = [entities]

    events: List[Dict[str, Any]] = []
    for index, event in enumerate(alert.get("events") or []):
        if index >= _MAX_EVENTS:
            break
        if not isinstance(event, dict):
            events.append({"message": str(event)[:_MAX_EVENT_CHARS]})
            continue
        message = (
            event.get("message")
            or event.get("reason")
            or event.get("process_name")
            or ""
        )
        text = str(message)
        if len(text) > _MAX_EVENT_CHARS:
            text = text[:_MAX_EVENT_CHARS] + "…"
        events.append(
            {
                "id": event.get("id") or event.get("_id"),
                "timestamp": event.get("timestamp") or event.get("@timestamp"),
                "host": event.get("host") or event.get("hostname"),
                "username": event.get("username") or event.get("user"),
                "ip": event.get("ip"),
                "process_name": event.get("process_name"),
                "message": text,
            }
        )

    comments: List[Any] = []
    for comment in alert.get("comments") or []:
        if isinstance(comment, dict):
            text = str(comment.get("comment") or comment.get("text") or "")
            if len(text) > _MAX_COMMENT_CHARS:
                text = text[:_MAX_COMMENT_CHARS] + "…"
            comments.append(
                {
                    "author": comment.get("author") or comment.get("created_by") or "unknown",
                    "timestamp": comment.get("timestamp") or comment.get("created_at"),
                    "comment": text,
                }
            )
        else:
            comments.append(str(comment)[:_MAX_COMMENT_CHARS])

    description = str(alert.get("description") or "").strip()
    if len(description) > _MAX_DESCRIPTION:
        description = description[:_MAX_DESCRIPTION] + "…"

    return {
        "id": alert.get("id") or alert.get("alert_id"),
        "title": alert.get("title") or "",
        "severity": alert.get("severity") or "",
        "priority": alert.get("priority") or "",
        "status": alert.get("status") or "",
        "verdict": alert.get("verdict") or "",
        "description": description,
        "created_at": alert.get("created_at") or "",
        "updated_at": alert.get("updated_at") or "",
        "related_entities": [str(item) for item in entities if item not in (None, "")],
        "events": events,
        "comments": comments,
    }


def _copy_alert_fields_into_payload(payload: Dict[str, Any], alert: Dict[str, Any]) -> None:
    """Fill common identity/host fields from the alert when the agent omitted them."""
    entities = alert.get("related_entities") or []
    entity_map = _entity_map(entities)

    def _set(key: str, *candidates: Any) -> None:
        if payload.get(key):
            return
        for value in candidates:
            if value not in (None, ""):
                payload[key] = value
                return

    _set("hostname", payload.get("hostname"), entity_map.get("host"), _host_from_events(alert))
    _set("username", payload.get("username"), entity_map.get("user"))
    _set("source_ip", payload.get("source_ip"), entity_map.get("ip"))
    if not payload.get("rule_name") and alert.get("title"):
        payload["rule_name"] = alert.get("title")
    if not payload.get("severity") and alert.get("severity"):
        payload["severity"] = alert.get("severity")
    if not payload.get("verdict") and alert.get("verdict"):
        payload["verdict"] = alert.get("verdict")
    if not payload.get("alert_status") and alert.get("status"):
        payload["alert_status"] = alert.get("status")
    if not payload.get("timestamp") and alert.get("created_at"):
        payload["timestamp"] = alert.get("created_at")


def _entity_map(entities: List[Any]) -> Dict[str, str]:
    mapped: Dict[str, str] = {}
    for item in entities:
        text = str(item)
        if ":" not in text:
            continue
        kind, value = text.split(":", 1)
        kind = kind.strip().lower()
        value = value.strip()
        if not value:
            continue
        if kind in {"user", "username"} and "user" not in mapped:
            mapped["user"] = value
        elif kind in {"ip", "source_ip"} and "ip" not in mapped:
            mapped["ip"] = value
        elif kind in {"host", "hostname"} and "host" not in mapped:
            mapped["host"] = value
        elif kind in {"hash", "sha256"} and "hash" not in mapped:
            mapped["hash"] = value
        elif kind in {"domain"} and "domain" not in mapped:
            mapped["domain"] = value
    return mapped


def _host_from_events(alert: Dict[str, Any]) -> Optional[str]:
    for event in alert.get("events") or []:
        if isinstance(event, dict) and event.get("host"):
            return str(event["host"])
    return None


def _humanize_text(
    *,
    action_type: str,
    title: str,
    summary: str,
    rationale: str,
    payload: Dict[str, Any],
    alert: Optional[Dict[str, Any]],
    catalog_description: str,
) -> Tuple[str, str, str]:
    alert = alert or {}
    rule_name = str(payload.get("rule_name") or alert.get("title") or "").strip()
    host = str(payload.get("hostname") or "").strip()
    user = str(payload.get("username") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    comment = str(payload.get("comment") or payload.get("description") or "").strip()
    activity = str(payload.get("activity") or "").strip()

    new_title = (title or "").strip()
    if _title_is_generic(new_title, action_type, payload.get("alert_id")):
        subject = rule_name or payload.get("alert_id") or payload.get("endpoint_id") or action_type
        suffix_bits = [bit for bit in (host, user) if bit]
        suffix = f" ({', '.join(suffix_bits)})" if suffix_bits else ""
        if action_type == "close_alert":
            reason_bit = f" [{reason}]" if reason else ""
            new_title = f"Close: {subject}{reason_bit}{suffix}"
        elif action_type == "identity_verify":
            new_title = f"Is this you? {user or subject}{suffix}"
        elif action_type in {"isolate_endpoint", "release_isolation"}:
            new_title = f"{'Isolate' if action_type == 'isolate_endpoint' else 'Release'}: {host or payload.get('endpoint_id') or subject}"
        elif action_type == "escalate":
            new_title = f"Escalate: {subject}{suffix}"
        else:
            new_title = f"{action_type}: {subject}{suffix}"
        new_title = new_title[:180]

    new_summary = (summary or "").strip()
    if _summary_is_generic(new_summary, catalog_description):
        lines: List[str] = []
        if rule_name:
            lines.append(f"Alert: {rule_name}")
        if alert.get("severity"):
            lines.append(f"Severity: {alert.get('severity')}")
        if alert.get("status"):
            lines.append(f"Status: {alert.get('status')}")
        if alert.get("verdict"):
            lines.append(f"Current verdict: {alert.get('verdict')}")
        if host:
            lines.append(f"Host: {host}")
        if user:
            lines.append(f"User: {user}")
        if payload.get("source_ip"):
            lines.append(f"Source IP: {payload.get('source_ip')}")
        if activity:
            lines.append(f"Activity: {activity}")
        if payload.get("timestamp") or alert.get("created_at"):
            lines.append(f"When: {payload.get('timestamp') or alert.get('created_at')}")
        if reason:
            lines.append(f"Proposed disposition: {reason}")
        if comment:
            lines.append(f"Agent comment: {comment}")
        entities = alert.get("related_entities") or []
        if entities:
            lines.append("Entities: " + ", ".join(str(item) for item in entities[:12]))
        new_summary = "\n".join(lines) if lines else (comment or catalog_description or new_summary)

    new_rationale = (rationale or "").strip()
    if not new_rationale:
        parts: List[str] = []
        if comment and comment not in new_summary:
            parts.append(comment)
        description = str(alert.get("description") or "").strip()
        if description:
            parts.append(description)
        events = alert.get("events") or []
        if events:
            parts.append("Triggering events:")
            for event in events[:5]:
                if not isinstance(event, dict):
                    parts.append(f"- {event}")
                    continue
                bits = [
                    str(event.get("timestamp") or ""),
                    str(event.get("host") or ""),
                    str(event.get("process_name") or ""),
                    str(event.get("message") or ""),
                ]
                parts.append("- " + " ".join(bit for bit in bits if bit).strip())
        comments = alert.get("comments") or []
        if comments:
            parts.append("Existing alert comments:")
            for item in comments[:5]:
                if isinstance(item, dict):
                    parts.append(
                        f"- {item.get('author') or 'unknown'}: {item.get('comment') or ''}"
                    )
                else:
                    parts.append(f"- {item}")
        new_rationale = "\n".join(parts).strip()

    return new_title, new_summary, new_rationale


def _title_is_generic(title: str, action_type: str, alert_id: Any) -> bool:
    if not title:
        return True
    lowered = title.lower().strip()
    if alert_id and lowered in {
        f"{action_type}: {alert_id}".lower(),
        f"close alert: {alert_id}".lower(),
    }:
        return True
    if lowered.startswith("close alert:") and alert_id and str(alert_id) in title:
        return True
    if lowered in {action_type, action_type.replace("_", " ")}:
        return True
    return False


def _summary_is_generic(summary: str, catalog_description: str) -> bool:
    if not summary:
        return True
    lowered = summary.strip().lower()
    if lowered in _GENERIC_SUMMARIES:
        return True
    if catalog_description and lowered == catalog_description.strip().lower():
        return True
    return False


def _default_identity_question(payload: Dict[str, Any]) -> str:
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
