"""Open findings, checked fields, and acknowledge or close.

Suggested means the dotted field is highlighted on the rule
(investigation_fields) or listed in suggested_fields.json. It only
changes the default checkbox. Acknowledge and close match other open
alerts for the same rule that contain every checked value, inside the
match lookback. A note is written only when the box has text. Neither
action edits a rule file. See documentation/detection-as-code.md.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from ...core.logging import get_logger
from ...core.errors import IntegrationError
from .errors import DetectionError
from .settings import stored_settings

logger = get_logger("sami.detection.findings")

_SKIP_PREFIXES = (
    # Rule text and the highlight list itself are not analyst evidence.
    # The highlight names are read separately by suggested_names_for.
    "kibana.alert.rule.parameters",
    "kibana.alert.rule.note",
    "signal.rule.note",
    "signal.rule.investigation_fields",
)


def normalize_entries(entries: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        field = str(entry.get("field") or "").strip()
        raw_value = entry.get("value")
        value = "" if raw_value is None else str(raw_value).strip()
        if not field or not value:
            continue
        key = (field, value)
        if key in seen:
            continue
        seen.add(key)
        found.append({"field": field, "value": value})
    return found


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and value not in ("", None)


def _flatten(source: Any, prefix: str = "", depth: int = 0) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    if depth > 5 or source is None:
        return rows
    if isinstance(source, dict):
        for key, value in source.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if any(name.startswith(skip) for skip in _SKIP_PREFIXES):
                continue
            rows.extend(_flatten(value, name, depth + 1))
        return rows
    if isinstance(source, list):
        scalars = [item for item in source if _is_scalar(item)]
        if scalars and len(scalars) == len(source):
            text = ", ".join(str(item) for item in scalars[:8])
            if len(text) > 500:
                text = text[:499] + "…"
            return [{"field": prefix, "value": text}]
        for item in source[:20]:
            rows.extend(_flatten(item, prefix, depth + 1))
        return rows
    if prefix and _is_scalar(source):
        text = str(source)
        if len(text) > 500:
            text = text[:499] + "…"
        return [{"field": prefix, "value": text}]
    return rows


def field_rows(source: Dict[str, Any], suggested_names: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    names = suggested_names or set()
    rows = []
    seen = set()
    for row in _flatten(source):
        key = (row["field"], row["value"])
        if key in seen or not row["field"]:
            continue
        seen.add(key)
        rows.append({
            "field": row["field"],
            "value": row["value"],
            "suggested": row["field"] in names,
        })
    rows.sort(key=lambda item: (not item["suggested"], item["field"]))
    return rows[:400]


def _highlighted_from_alert(source: Dict[str, Any]) -> Set[str]:
    """Highlighted names Elastic copied onto the alert, when the file is not on disk."""
    from .rules_store import field_name_set

    signal = source.get("signal") if isinstance(source.get("signal"), dict) else {}
    rule = signal.get("rule") if isinstance(signal.get("rule"), dict) else {}
    names = field_name_set(rule.get("investigation_fields"))
    names |= field_name_set(source.get("kibana.alert.rule.investigation_fields"))
    return names


def suggested_names_for(source: Dict[str, Any], rule_id: str = "", rule_name: str = "") -> Set[str]:
    """Rule highlighted fields, plus any extras listed in suggested_fields.json."""
    from . import rules_store

    names = set(rules_store.load_suggested_fields())
    names |= _highlighted_from_alert(source)
    if rule_id or rule_name:
        try:
            _path, data, _digest = rules_store.load_rule_file(rule_id=rule_id or None, rule_name=rule_name or None)
        except DetectionError:
            data = {}
        names |= rules_store.highlighted_field_names(data)
    return names


def _lookup(source: Dict[str, Any], *names: str) -> str:
    fields = {row["field"]: row["value"] for row in field_rows(source)}
    for name in names:
        if fields.get(name):
            return fields[name]
    return ""


def summarize_alert(alert_id: str, source: Dict[str, Any]) -> Dict[str, Any]:
    signal = source.get("signal") if isinstance(source.get("signal"), dict) else {}
    rule = signal.get("rule") if isinstance(signal.get("rule"), dict) else {}
    signal_ai = signal.get("ai") if isinstance(signal.get("ai"), dict) else {}
    rule_name = (
        rule.get("name")
        or source.get("kibana.alert.rule.name")
        or source.get("message")
        or ""
    )
    rule_id = (
        rule.get("rule_id")
        or rule.get("id")
        or source.get("kibana.alert.rule.uuid")
        or source.get("kibana.alert.rule.rule_id")
        or ""
    )
    return {
        "id": alert_id,
        "title": str(rule_name),
        "rule_name": str(rule_name),
        "rule_id": str(rule_id),
        "severity": str(signal.get("severity") or source.get("kibana.alert.severity") or "medium"),
        "status": str(signal.get("status") or source.get("kibana.alert.workflow_status") or "open"),
        "created_at": str(source.get("@timestamp") or ""),
        "host_name": _lookup(source, "host.name", "host.hostname"),
        "user_name": _lookup(source, "user.name"),
        "verdict": str(signal_ai.get("verdict") or ""),
    }


def values_by_field(source: Dict[str, Any]) -> Dict[str, Set[str]]:
    found: Dict[str, Set[str]] = {}
    for row in field_rows(source):
        found.setdefault(row["field"], set()).add(row["value"])
    return found


def document_matches(source: Dict[str, Any], entries: List[Dict[str, str]]) -> bool:
    """True when every checked field/value pair is present. Extra fields on the alert are ignored."""
    found = values_by_field(source)
    for entry in entries:
        if entry["value"] not in found.get(entry["field"], set()):
            return False
    return True


def finding_detail(client: Any, alert_id: str) -> Dict[str, Any]:
    try:
        source = client.get_raw_alert_document(alert_id)
    except IntegrationError as exc:
        raise DetectionError(str(exc), status_code=404) from exc
    summary = summarize_alert(alert_id, source)
    names = suggested_names_for(source, str(summary.get("rule_id") or ""), str(summary.get("rule_name") or ""))
    return {**summary, "fields": field_rows(source, names)}


def list_findings(client: Any, *, hours: Optional[int] = None, query: str = "") -> List[Dict[str, Any]]:
    lookback = stored_settings()["findings_hours"] if hours is None else max(1, int(hours))
    try:
        alerts = client.get_security_alerts(
            hours_back=lookback,
            max_alerts=100,
            status_filter="open",
            include_investigated=True,
        )
    except IntegrationError as exc:
        raise DetectionError(str(exc), status_code=502) from exc
    needle = (query or "").strip().lower()
    if not needle:
        return alerts
    return [
        alert for alert in alerts
        if needle in " ".join(
            str(alert.get(key) or "")
            for key in ("title", "rule_name", "rule_id", "severity", "host_name")
        ).lower()
    ]


def matching_alert_ids(client: Any, *, rule_id: str, alert_id: str, entries: List[Dict[str, str]]) -> List[str]:
    ids: List[str] = []
    if alert_id:
        ids.append(alert_id)
    if not rule_id:
        return ids
    try:
        documents = client.search_alert_documents(
            rule_id=rule_id,
            status="open",
            hours_back=stored_settings()["match_hours"],
        )
    except IntegrationError as exc:
        logger.warning("Could not search matching alerts for %s: %s", rule_id, exc)
        return ids
    for document in documents:
        candidate = str(document.get("id") or "")
        source = document.get("source") if isinstance(document.get("source"), dict) else {}
        if not candidate or candidate in ids:
            continue
        if document_matches(source, entries):
            ids.append(candidate)
    return ids


def update_finding_status(
    client: Any,
    *,
    alert_id: str,
    rule_id: str,
    entries: List[Dict[str, str]],
    status: str,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    status = (status or "").strip().lower()
    if status not in {"acknowledged", "closed"}:
        raise DetectionError("Status must be acknowledged or closed.")
    checked = normalize_entries(entries)
    if not checked:
        raise DetectionError("Check at least one field.")
    note_text = (note or "").strip()
    targets = matching_alert_ids(client, rule_id=rule_id, alert_id=alert_id, entries=checked)
    updated: List[str] = []
    failed: List[Dict[str, str]] = []
    notes_written: List[str] = []
    for target in targets:
        try:
            if note_text:
                client.add_alert_note(target, note_text)
                notes_written.append(target)
            if status == "closed":
                client.close_alert(target, reason="false_positive", comment=None)
            else:
                client.set_alert_workflow_status(target, "acknowledged")
            updated.append(target)
        except IntegrationError as exc:
            failed.append({"alert_id": target, "error": str(exc)})
    if not updated and failed:
        raise DetectionError(failed[0]["error"], status_code=502)
    return {
        "status": status,
        "updated": updated,
        "failed": failed,
        "notes_written": notes_written,
        "note": bool(note_text),
    }
