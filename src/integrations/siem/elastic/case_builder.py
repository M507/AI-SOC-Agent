"""Build Elastic Security case titles and descriptions from alert + identity context."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

_MAX_DESCRIPTION = 24000
_MAX_EVENTS = 10
_MAX_EVENT_CHARS = 500


def kibana_severity(value: Optional[str]) -> str:
    raw = (value or "high").strip().lower()
    mapping = {
        "low": "low",
        "medium": "medium",
        "med": "medium",
        "high": "high",
        "critical": "critical",
        "crit": "critical",
    }
    return mapping.get(raw, "high")


def default_case_title(
    *,
    alert: Optional[Dict[str, Any]] = None,
    identity: Optional[Dict[str, Any]] = None,
    fallback: str = "Unauthorized activity",
) -> str:
    alert = alert or {}
    identity = identity or {}
    alert_title = str(alert.get("title") or "").strip()
    entity = (
        identity.get("username")
        or identity.get("hostname")
        or identity.get("source_ip")
        or _primary_entity(alert.get("related_entities") or [])
        or "unknown"
    )
    when = identity.get("timestamp") or alert.get("created_at") or ""
    date_part = str(when)[:10] if when else ""
    kind = identity.get("activity") or alert_title or fallback
    parts = [str(kind).strip() or fallback, str(entity)]
    if date_part:
        parts.append(date_part)
    return " - ".join(parts)[:180]


def build_elastic_case_description(
    *,
    notes: str = "",
    alert: Optional[Dict[str, Any]] = None,
    identity: Optional[Dict[str, Any]] = None,
) -> str:
    """Markdown description following standards/case_standard.md."""
    sections: List[str] = []
    notes = (notes or "").strip()
    if notes:
        sections.append("## Investigation notes\n\n" + notes)

    identity_block = _identity_section(identity or {})
    if identity_block:
        sections.append(identity_block)

    if alert:
        sections.append(_alert_section(alert))
        entities = alert.get("related_entities") or []
        if entities:
            sections.append("## Key entities\n\n" + _bullets(entities))
        events = alert.get("events") or []
        if events:
            sections.append("## Triggering events\n\n" + _events_block(events))
        comments = alert.get("comments") or []
        if comments:
            sections.append("## Alert comments\n\n" + _comments_block(comments))

    body = "\n\n".join(section for section in sections if section).strip()
    if not body:
        body = "Escalated from SamiGPT. No additional alert details were available."
    if len(body) > _MAX_DESCRIPTION:
        body = body[: _MAX_DESCRIPTION - 20].rstrip() + "\n\n…(truncated)"
    return body


def _identity_section(identity: Dict[str, Any]) -> str:
    rows = [
        ("User", identity.get("username")),
        ("Activity", identity.get("activity")),
        ("Source IP", identity.get("source_ip")),
        ("Host", identity.get("hostname")),
        ("When", identity.get("timestamp")),
    ]
    lines = [f"- **{label}:** {value}" for label, value in rows if value]
    if not lines:
        return ""
    header = "## Identity verification\n\nAnalyst answered **No** — this was not the user."
    return header + "\n\n" + "\n".join(lines)


def _alert_section(alert: Dict[str, Any]) -> str:
    lines = ["## Alert"]
    fields = [
        ("ID", alert.get("id") or alert.get("alert_id")),
        ("Title", alert.get("title")),
        ("Severity", alert.get("severity")),
        ("Priority", alert.get("priority")),
        ("Status", alert.get("status")),
        ("Verdict", alert.get("verdict")),
        ("Created", alert.get("created_at")),
        ("Updated", alert.get("updated_at")),
    ]
    for label, value in fields:
        if value not in (None, ""):
            lines.append(f"- **{label}:** {value}")
    description = str(alert.get("description") or "").strip()
    if description:
        lines.append("")
        lines.append(description)
    return "\n".join(lines)


def _events_block(events: Iterable[Any]) -> str:
    parts: List[str] = []
    for index, event in enumerate(events):
        if index >= _MAX_EVENTS:
            parts.append(f"- … {index} additional events omitted")
            break
        if isinstance(event, dict):
            event_id = event.get("id") or event.get("_id") or ""
            ts = event.get("timestamp") or event.get("@timestamp") or ""
            message = event.get("message") or event.get("reason") or str(event)
            host = event.get("host") or event.get("hostname") or ""
            text = f"{ts} {host} {message}".strip()
        else:
            event_id = ""
            text = str(event)
        if len(text) > _MAX_EVENT_CHARS:
            text = text[:_MAX_EVENT_CHARS] + "…"
        prefix = f"`{event_id}` " if event_id else ""
        parts.append(f"- {prefix}{text}".rstrip())
    return "\n".join(parts) if parts else "_None_"


def _comments_block(comments: Iterable[Any]) -> str:
    parts: List[str] = []
    for comment in comments:
        if isinstance(comment, dict):
            author = comment.get("author") or "unknown"
            ts = comment.get("timestamp") or ""
            text = comment.get("comment") or comment.get("text") or str(comment)
            parts.append(f"- **{author}** {ts}: {text}".rstrip())
        else:
            parts.append(f"- {comment}")
    return "\n".join(parts)


def _bullets(values: Iterable[Any]) -> str:
    return "\n".join(f"- {item}" for item in values if item not in (None, ""))


def _primary_entity(entities: List[Any]) -> str:
    for item in entities:
        text = str(item)
        if ":" in text:
            return text.split(":", 1)[1]
        if text:
            return text
    return ""
