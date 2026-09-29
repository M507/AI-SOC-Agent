"""Landing-page counts from records the console already keeps."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..approval_queue.catalog import get_action_spec
from ..approval_queue.models import ApprovalRequest, RequestStatus

RANGES = ("7d", "30d", "all")

_OPEN = {
    RequestStatus.PENDING,
    RequestStatus.AWAITING_INTEGRATION,
}
_SETTLED = {
    RequestStatus.EXECUTED,
    RequestStatus.DENIED,
    RequestStatus.FAILED,
    RequestStatus.ACKNOWLEDGED,
}

_DECISIONS = (
    ("false_positive", "False positives"),
    ("benign_true_positive", "Benign true positives"),
)
_DETECTION = (
    ("fine_tune", "Fine-tune"),
    ("visibility", "Visibility gaps"),
    ("runbook_gap", "Runbook gaps"),
)
_RESPONSE = (
    ("isolate_endpoint", "Isolations"),
    ("release_isolation", "Isolation releases"),
    ("kill_process", "Process kills"),
    ("collect_forensics", "Forensic collections"),
    ("create_case", "Cases opened"),
    ("close_case", "Cases closed"),
)


def range_start(range_key: str, now: Optional[datetime] = None) -> Optional[datetime]:
    if range_key not in RANGES:
        raise ValueError(f"Unknown range {range_key!r}")
    if range_key == "all":
        return None
    days = 7 if range_key == "7d" else 30
    return _naive(now or datetime.now()) - timedelta(days=days)


_OUTCOMES = (
    ("executed", "Done"),
    ("denied", "Denied"),
    ("failed", "Failed"),
    ("acknowledged", "Reviewed"),
)
_BUCKET_CAP = 30


def build_overview(
    requests: Sequence[ApprovalRequest],
    sessions: Sequence[Any],
    autoruns: Sequence[Any],
    spend: Optional[Dict[str, Any]],
    range_key: str,
    now: Optional[datetime] = None,
    spend_events: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    moment = _naive(now or datetime.now())
    start = range_start(range_key, moment)
    window = [item for item in requests if _in_range(item.created_at, start)]
    decisions = {key: 0 for key, _label in _DECISIONS}
    decisions["escalations"] = 0
    detection = {key: 0 for key, _label in _DETECTION}
    response = {key: 0 for key, _label in _RESPONSE}
    waiting = 0
    outcomes = {key: 0 for key, _label in _OUTCOMES}
    for item in window:
        if item.status in _OPEN:
            waiting += 1
        if item.action_type in detection:
            detection[item.action_type] += 1
        if item.status.value in outcomes:
            outcomes[item.status.value] += 1
        if item.status != RequestStatus.EXECUTED:
            continue
        if item.action_type == "close_alert":
            reason = str((item.payload or {}).get("reason") or "").strip().lower()
            if reason in decisions:
                decisions[reason] += 1
        elif item.action_type == "escalate":
            decisions["escalations"] += 1
        elif item.action_type in response:
            response[item.action_type] += 1

    recent = sorted(
        (item for item in window if item.status in _SETTLED),
        key=lambda item: _naive(item.updated_at),
        reverse=True,
    )[:8]
    unit, buckets, capped = _axis(requests, spend_events or [], start, range_key, moment)
    activity, spend_series, unpriced = _fill_series(
        requests, spend_events or [], start, buckets, unit == "week"
    )

    return {
        "success": True,
        "range": range_key,
        "decisions": _cards(_DECISIONS + (("escalations", "Escalations"),), decisions),
        "waiting": [{"id": "open", "label": "Open requests", "count": waiting}],
        "attention": _attention(requests),
        "activity": activity,
        "series_unit": unit,
        "series_capped": capped,
        "outcomes": _cards(_OUTCOMES, outcomes),
        "detection": _cards(_DETECTION, detection),
        "response": _cards(_RESPONSE, response),
        "spend_series": spend_series,
        "spend_unpriced": unpriced,
        "work": [
            {
                "id": "sessions",
                "label": "Sessions",
                "count": _count_dated(sessions, start),
                "go": "sessions",
            },
            {
                "id": "autoruns",
                "label": "Autoruns",
                "count": _count_dated(autoruns, start),
                "go": "autoruns",
            },
            {
                "id": "spend",
                "label": "Spend",
                "value": (spend or {}).get("cost_label") or "—",
                "go": "cost",
            },
        ],
        "recent": [_recent_row(item) for item in recent],
    }


def _attention(requests: Sequence[ApprovalRequest]) -> Dict[str, int]:
    pending = awaiting = informational = 0
    for item in requests:
        if item.status == RequestStatus.PENDING:
            pending += 1
        elif item.status == RequestStatus.AWAITING_INTEGRATION:
            awaiting += 1
        elif item.status == RequestStatus.INFORMATIONAL:
            informational += 1
    return {"pending": pending, "awaiting": awaiting, "informational": informational}


def _axis(
    requests: Sequence[ApprovalRequest],
    events: Sequence[Dict[str, Any]],
    start: Optional[datetime],
    range_key: str,
    moment: datetime,
) -> tuple:
    if range_key != "all" and start is not None:
        return "day", _inclusive_days(start.date(), moment.date()), False
    dates = []
    for item in requests:
        created = _stamp(item.created_at)
        if created is not None and _in_range(created, start):
            dates.append(created.date())
        if item.status in _SETTLED:
            updated = _stamp(item.updated_at)
            if updated is not None and _in_range(updated, start):
                dates.append(updated.date())
    for event in events:
        stamp = _stamp(event.get("at"))
        if stamp is not None and _in_range(stamp, start):
            dates.append(stamp.date())
    if not dates:
        return "day", [], False
    first, last = min(dates), max(dates)
    if (last - first).days > 60:
        weeks = _inclusive_weeks(first, last)
        capped = len(weeks) > _BUCKET_CAP
        return "week", weeks[-_BUCKET_CAP:], capped
    days = _inclusive_days(first, last)
    capped = len(days) > _BUCKET_CAP
    return "day", days[-_BUCKET_CAP:], capped


def _fill_series(
    requests: Sequence[ApprovalRequest],
    events: Sequence[Dict[str, Any]],
    start: Optional[datetime],
    buckets: List[str],
    weekly: bool,
) -> tuple:
    seen = set(buckets)
    filed = {key: 0 for key in buckets}
    settled = {key: 0 for key in buckets}
    spent = {key: 0.0 for key in buckets}
    unpriced = False
    for item in requests:
        created = _stamp(item.created_at)
        if created is not None and _in_range(created, start):
            key = _bucket_key(created, weekly)
            if key in seen:
                filed[key] += 1
        if item.status in _SETTLED:
            updated = _stamp(item.updated_at)
            if updated is not None and _in_range(updated, start):
                key = _bucket_key(updated, weekly)
                if key in seen:
                    settled[key] += 1
    for event in events:
        stamp = _stamp(event.get("at"))
        if stamp is None or not _in_range(stamp, start):
            continue
        if event.get("usage_reported") and not event.get("priced"):
            unpriced = True
        amount = event.get("cost_usd")
        if not event.get("priced") or amount is None:
            continue
        key = _bucket_key(stamp, weekly)
        if key in seen:
            spent[key] += float(amount)
    activity = [
        {"bucket": key, "filed": filed[key], "settled": settled[key]} for key in buckets
    ]
    spend_series = [
        {"bucket": key, "cost_usd": round(spent[key], 6)} for key in buckets
    ]
    return activity, spend_series, unpriced


def _bucket_key(when: datetime, weekly: bool) -> str:
    day = when.date()
    if weekly:
        day = day - timedelta(days=day.weekday())
    return day.isoformat()


def _inclusive_days(first, last) -> List[str]:
    keys = []
    day = first
    while day <= last:
        keys.append(day.isoformat())
        day += timedelta(days=1)
    return keys


def _inclusive_weeks(first, last) -> List[str]:
    start = first - timedelta(days=first.weekday())
    end = last - timedelta(days=last.weekday())
    keys = []
    day = start
    while day <= end:
        keys.append(day.isoformat())
        day += timedelta(days=7)
    return keys


def _cards(spec: Iterable[tuple], counts: Dict[str, int]) -> List[Dict[str, Any]]:
    return [{"id": key, "label": label, "count": counts[key]} for key, label in spec]


def _recent_row(item: ApprovalRequest) -> Dict[str, Any]:
    spec = get_action_spec(item.action_type)
    return {
        "id": item.id,
        "title": item.title or (spec.label if spec else item.action_type),
        "label": spec.label if spec else item.action_type,
        "status": item.status.value,
        "at": _naive(item.updated_at).isoformat(timespec="seconds"),
    }


def _count_dated(items: Sequence[Any], start: Optional[datetime]) -> int:
    return sum(1 for item in items if _in_range(getattr(item, "created_at", None), start))


def _stamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return _naive(value)
    if isinstance(value, str) and value:
        try:
            return _naive(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _in_range(when: Optional[datetime], start: Optional[datetime]) -> bool:
    if start is None or when is None:
        return True
    return _naive(when) >= start


def _naive(when: datetime) -> datetime:
    if when.tzinfo is not None:
        return when.astimezone().replace(tzinfo=None)
    return when
