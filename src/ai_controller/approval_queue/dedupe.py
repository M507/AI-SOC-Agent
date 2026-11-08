"""IR-correct request matching: same alert document vs rule-scoped recommendations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .models import ApprovalRequest, RequestStatus, is_archived

ALERT_SCOPED_ACTIONS = frozenset({"add_alert_note", "close_alert"})
INFORMATIONAL_ACTIONS = frozenset({"fine_tune", "visibility", "runbook_gap"})
ENDPOINT_SCOPED_ACTIONS = frozenset({"isolate_endpoint", "release_isolation"})
_OPEN = frozenset(
    {
        RequestStatus.PENDING,
        RequestStatus.INFORMATIONAL,
        RequestStatus.AWAITING_INTEGRATION,
    }
)

_OBSERVABLE_RE = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-fA-F0-9]{32,64}"
    r"|https?://\S+"
    r"|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    r")\b"
)


@dataclass(frozen=True)
class EnqueueOutcome:
    request: ApprovalRequest
    outcome: str  # created | deduplicated | updated


def is_open_request(request: ApprovalRequest) -> bool:
    return (not is_archived(request)) and request.status in _OPEN


def alert_id_of(request: ApprovalRequest) -> Optional[str]:
    payload = request.payload or {}
    for key in ("alert_id", "alertId"):
        raw = payload.get(key)
        if raw not in (None, ""):
            return str(raw)
    alert = payload.get("alert")
    if isinstance(alert, dict):
        for key in ("id", "alert_id", "alertId"):
            raw = alert.get(key)
            if raw not in (None, ""):
                return str(raw)
    return None


def rule_key_of(payload: Optional[Dict[str, Any]], title: str = "", summary: str = "") -> str:
    """Stable key for informational Notes: prefer rule_id, then rule name, then theme."""
    payload = payload or {}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    for candidate in (
        payload.get("rule_id"),
        rule.get("rule_id"),
        rule.get("id"),
        payload.get("rule_name"),
        rule.get("name"),
        payload.get("ntopng_script"),
        rule.get("script"),
    ):
        text = str(candidate or "").strip().lower()
        if text:
            return f"rule:{text}"
    theme = _normalize_theme(
        " ".join(
            bit
            for bit in (
                str(payload.get("title") or ""),
                title,
                summary,
                str(payload.get("suggestion") or ""),
                str(payload.get("description") or ""),
            )
            if bit
        )
    )
    return f"theme:{theme}" if theme else ""


def informational_fingerprint(
    action_type: str,
    payload: Optional[Dict[str, Any]],
    *,
    title: str = "",
    summary: str = "",
    cluster_id: Optional[str] = None,
) -> str:
    rule = rule_key_of(payload, title=title, summary=summary)
    cluster = (cluster_id or "").strip() or "_"
    return f"{cluster}|{action_type}|{rule}"


def note_is_richer(existing_note: str, new_note: str) -> bool:
    """True when the new note adds length or concrete observables the old one lacked."""
    old = (existing_note or "").strip()
    new = (new_note or "").strip()
    if not new:
        return False
    if not old:
        return True
    if len(new) >= len(old) + 40:
        return True
    old_obs = set(_OBSERVABLE_RE.findall(old))
    new_obs = set(_OBSERVABLE_RE.findall(new))
    if new_obs - old_obs:
        return True
    # Placeholder / "need more data" → concrete disposition
    vague = ("request ", "need ", "missing ", "unable ", "to determine", "to verify")
    old_vague = any(token in old.lower() for token in vague)
    new_concrete = any(
        token in new.lower()
        for token in ("benign", "false positive", "true positive", "malicious", "closed", "escalat")
    )
    return old_vague and new_concrete and len(new) >= len(old)


def _payload_host_dst(payload: Optional[Dict[str, Any]]) -> tuple[str, str]:
    payload = payload or {}
    obs = distinguishing_observables(payload)
    host = str(
        payload.get("hostname")
        or obs.get("host")
        or obs.get("src")
        or payload.get("source_ip")
        or ""
    ).strip().lower()
    dst = str(
        payload.get("destination_ip")
        or payload.get("dst_ip")
        or obs.get("dst")
        or ""
    ).strip().lower()
    return host, dst


def flow_fingerprint(
    action_type: str,
    payload: Optional[Dict[str, Any]],
    *,
    cluster_id: Optional[str] = None,
) -> str:
    """
    Collapse lookalike Approvals: same action + rule + host → dst.
    Used when distinct SIEM alert_ids are the same noisy flow pattern.
    """
    payload = payload or {}
    host, dst = _payload_host_dst(payload)
    rule = rule_key_of(payload)
    if not host or not rule:
        return ""
    cluster = (cluster_id or "").strip() or "_"
    # Prefer host→dst; fall back to host-only (e.g. scan detections without peer).
    peer = dst or "_"
    return f"{cluster}|{action_type}|{rule}|host:{host}|dst:{peer}"


def endpoint_fingerprint(
    action_type: str,
    payload: Optional[Dict[str, Any]],
    *,
    cluster_id: Optional[str] = None,
) -> str:
    payload = payload or {}
    endpoint = str(
        payload.get("endpoint_id")
        or payload.get("hostname")
        or payload.get("agent_id")
        or ""
    ).strip().lower()
    if not endpoint or action_type not in ENDPOINT_SCOPED_ACTIONS:
        return ""
    cluster = (cluster_id or "").strip() or "_"
    return f"{cluster}|{action_type}|endpoint:{endpoint}"


def related_alert_ids_of(request: ApprovalRequest) -> List[str]:
    payload = request.payload or {}
    ids: List[str] = []
    primary = alert_id_of(request)
    if primary:
        ids.append(primary)
    extra = payload.get("related_alert_ids") or payload.get("alert_ids") or []
    if isinstance(extra, str):
        extra = [part.strip() for part in extra.split(",") if part.strip()]
    if isinstance(extra, list):
        for raw in extra:
            text = str(raw or "").strip()
            if text and text not in ids:
                ids.append(text)
    return ids


def find_open_alert_match(
    items: Iterable[ApprovalRequest],
    *,
    action_type: str,
    alert_id: str,
    cluster_id: Optional[str] = None,
) -> Optional[ApprovalRequest]:
    if action_type not in ALERT_SCOPED_ACTIONS or not alert_id:
        return None
    target = str(alert_id)
    for item in items:
        if not is_open_request(item):
            continue
        if item.action_type != action_type:
            continue
        if cluster_id and item.cluster_id and item.cluster_id != cluster_id:
            continue
        if target in related_alert_ids_of(item):
            return item
    return None


def find_open_flow_match(
    items: Iterable[ApprovalRequest],
    *,
    action_type: str,
    payload: Optional[Dict[str, Any]],
    cluster_id: Optional[str] = None,
) -> Optional[ApprovalRequest]:
    if action_type not in ALERT_SCOPED_ACTIONS:
        return None
    target = flow_fingerprint(action_type, payload, cluster_id=cluster_id)
    if not target:
        return None
    for item in items:
        if not is_open_request(item):
            continue
        if item.action_type != action_type:
            continue
        if cluster_id and item.cluster_id and item.cluster_id != cluster_id:
            continue
        existing = flow_fingerprint(
            item.action_type,
            item.payload,
            cluster_id=item.cluster_id or cluster_id,
        )
        if existing and existing == target:
            return item
    return None


def find_open_endpoint_match(
    items: Iterable[ApprovalRequest],
    *,
    action_type: str,
    payload: Optional[Dict[str, Any]],
    cluster_id: Optional[str] = None,
) -> Optional[ApprovalRequest]:
    target = endpoint_fingerprint(action_type, payload, cluster_id=cluster_id)
    if not target:
        return None
    for item in items:
        if not is_open_request(item):
            continue
        if item.action_type != action_type:
            continue
        if cluster_id and item.cluster_id and item.cluster_id != cluster_id:
            continue
        existing = endpoint_fingerprint(
            item.action_type,
            item.payload,
            cluster_id=item.cluster_id or cluster_id,
        )
        if existing and existing == target:
            return item
    return None


def find_open_informational_match(
    items: Iterable[ApprovalRequest],
    *,
    action_type: str,
    payload: Optional[Dict[str, Any]],
    title: str = "",
    summary: str = "",
    cluster_id: Optional[str] = None,
) -> Optional[ApprovalRequest]:
    if action_type not in INFORMATIONAL_ACTIONS:
        return None
    target = informational_fingerprint(
        action_type,
        payload,
        title=title,
        summary=summary,
        cluster_id=cluster_id,
    )
    if not target.endswith("|") and target.rsplit("|", 1)[-1] in {"", "theme:"}:
        return None
    for item in items:
        if not is_open_request(item):
            continue
        if item.action_type != action_type:
            continue
        if cluster_id and item.cluster_id and item.cluster_id != cluster_id:
            continue
        existing = informational_fingerprint(
            item.action_type,
            item.payload,
            title=item.title,
            summary=item.summary,
            cluster_id=item.cluster_id or cluster_id,
        )
        if existing == target:
            return item
    return None


def find_related_requests(
    items: Sequence[ApprovalRequest],
    *,
    alert_id: Optional[str] = None,
    action_types: Optional[Sequence[str]] = None,
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    query: Optional[str] = None,
    cluster_id: Optional[str] = None,
    open_only: bool = True,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Compact list of related open (or all) requests for the AI to inspect."""
    wanted_actions: Optional[Set[str]] = None
    if action_types:
        wanted_actions = {str(item).strip() for item in action_types if str(item).strip()}
    rule_needles = {
        str(value).strip().lower()
        for value in (rule_id, rule_name)
        if value not in (None, "")
    }
    query_l = (query or "").strip().lower()
    alert_filter = str(alert_id).strip() if alert_id not in (None, "") else ""
    matches: List[ApprovalRequest] = []
    for item in items:
        if open_only and not is_open_request(item):
            continue
        if cluster_id and item.cluster_id and item.cluster_id != cluster_id:
            continue
        if wanted_actions and item.action_type not in wanted_actions:
            continue
        payload = item.payload or {}
        item_alert = alert_id_of(item) or ""

        if alert_filter:
            # Alert-scoped rows must match the id; informational rows may still
            # match via rule/query filters without sharing the alert_id.
            if item.action_type in ALERT_SCOPED_ACTIONS and item_alert != alert_filter:
                continue
            if (
                item.action_type not in ALERT_SCOPED_ACTIONS
                and item_alert
                and item_alert != alert_filter
                and not rule_needles
                and not query_l
            ):
                continue

        if rule_needles:
            rule_obj = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
            hay = " ".join(
                str(bit or "")
                for bit in (
                    payload.get("rule_id"),
                    payload.get("rule_name"),
                    rule_obj.get("name"),
                    rule_obj.get("rule_id"),
                    item.title,
                    item.summary,
                )
            ).lower()
            if not any(needle in hay for needle in rule_needles):
                continue

        if query_l:
            blob = " ".join(
                str(bit or "")
                for bit in (
                    item.title,
                    item.summary,
                    item.rationale,
                    payload.get("note"),
                    payload.get("suggestion"),
                )
            ).lower()
            if query_l not in blob:
                continue

        if not alert_filter and not rule_needles and not query_l and not wanted_actions:
            continue

        matches.append(item)
        if len(matches) >= max(1, min(int(limit or 25), 100)):
            break
    return [_compact(item) for item in matches]


def _compact(item: ApprovalRequest) -> Dict[str, Any]:
    payload = item.payload or {}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    summary = (item.summary or "").strip()
    if len(summary) > 240:
        summary = summary[:240] + "…"
    return {
        "id": item.id,
        "action_type": item.action_type,
        "status": item.status.value,
        "title": item.title,
        "summary": summary,
        "alert_id": alert_id_of(item),
        "rule_id": payload.get("rule_id") or rule.get("rule_id") or rule.get("id"),
        "rule_name": payload.get("rule_name") or rule.get("name"),
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "session_id": item.session_id,
        "cluster_id": item.cluster_id,
    }


def _normalize_theme(text: str) -> str:
    lowered = text.lower()
    # Collapse common connectivity-check / empty-UA phrasings to one theme bucket.
    if any(
        token in lowered
        for token in (
            "connectivity-check",
            "connectivity check",
            "empty user-agent",
            "empty user agent",
            "suspicious_user_agent",
            "ndpi_http_suspicious_user_agent",
        )
    ):
        return "ntopng_empty_ua_connectivity_check"
    tokens = re.findall(r"[a-z0-9]+", lowered)
    stop = {
        "add",
        "the",
        "a",
        "an",
        "for",
        "to",
        "of",
        "and",
        "or",
        "with",
        "from",
        "rule",
        "alert",
        "fine",
        "tune",
        "tuning",
        "visibility",
        "runbook",
        "recommendation",
        "exception",
        "whitelist",
        "exclude",
        "suppress",
    }
    keep = [tok for tok in tokens if tok not in stop and len(tok) > 2][:12]
    return "_".join(keep)


def distinguishing_observables(payload: Optional[Dict[str, Any]], alert: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Host / dst / script / port / target for readable Approval titles."""
    import json

    payload = payload or {}
    alert = alert or (payload.get("alert") if isinstance(payload.get("alert"), dict) else {}) or {}
    entities = alert.get("related_entities") or []
    entity_map: Dict[str, str] = {}
    ip_list: List[str] = []
    for item in entities:
        text = str(item)
        if ":" not in text:
            continue
        kind, value = text.split(":", 1)
        kind = kind.strip().lower()
        value = value.strip()
        if not value:
            continue
        if kind == "ip":
            if value not in ip_list:
                ip_list.append(value)
        elif kind not in entity_map:
            entity_map[kind] = value

    # ntopng flow alerts often stash cli/srv in the first event message JSON.
    flow: Dict[str, Any] = {}
    for event in alert.get("events") or []:
        if not isinstance(event, dict):
            continue
        message = event.get("message")
        if isinstance(message, str) and message.lstrip().startswith("{"):
            try:
                parsed = json.loads(message)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                flow = parsed
                break
        if isinstance(message, dict):
            flow = message
            break

    host = str(
        payload.get("hostname")
        or entity_map.get("host")
        or entity_map.get("hostname")
        or alert.get("host_name")
        or ""
    ).strip()
    src = str(
        payload.get("source_ip")
        or entity_map.get("source_ip")
        or flow.get("cli_ip")
        or (ip_list[0] if ip_list else "")
        or entity_map.get("ip")
        or ""
    ).strip()
    dst = str(
        payload.get("destination_ip")
        or payload.get("dst_ip")
        or entity_map.get("destination_ip")
        or entity_map.get("dst")
        or flow.get("srv_ip")
        or ""
    ).strip()
    if not dst:
        for candidate in ip_list:
            if candidate not in {host, src}:
                dst = candidate
                break
    port = str(
        payload.get("destination_port")
        or payload.get("dst_port")
        or entity_map.get("port")
        or flow.get("srv_port")
        or ""
    ).strip()
    target = str(payload.get("target") or alert.get("target") or "").strip()
    script = str(
        payload.get("ntopng_script")
        or payload.get("subtitle")
        or alert.get("subtitle")
        or flow.get("script")
        or flow.get("alert_name")
        or ""
    ).strip()
    reason = str(payload.get("reason_detail") or alert.get("reason") or "").strip()
    # Parse "a → b" style targets
    if not dst and "→" in target:
        parts = [bit.strip() for bit in target.split("→", 1)]
        if len(parts) == 2:
            if not host:
                host = parts[0]
            dst = parts[1]
    if not dst and target and target[0].isdigit():
        dst = target.split()[0] if target else dst
    if not host and src:
        host = src

    out = {}
    if host:
        out["host"] = host
    if src and src != host:
        out["src"] = src
    if dst:
        out["dst"] = dst
    if port:
        out["port"] = port
    if script:
        out["script"] = script
    if target and target not in {host, dst, f"{host} → {dst}"}:
        out["target"] = target[:80]
    if reason and len(reason) < 60:
        out["reason"] = reason
    return out


def build_observable_title(
    action_type: str,
    *,
    rule_name: str,
    observables: Dict[str, str],
    reason: str = "",
) -> str:
    subject = (rule_name or "alert").strip()
    script = observables.get("script")
    if script and script.lower() not in subject.lower():
        subject = f"{subject} · {script}"
    host = observables.get("host") or observables.get("src") or ""
    dst = observables.get("dst") or ""
    port = observables.get("port") or ""
    target = observables.get("target") or ""
    flow = ""
    if host and dst:
        flow = f"{host} → {dst}" + (f":{port}" if port else "")
    elif host:
        flow = host + (f":{port}" if port else "")
    elif dst:
        flow = dst + (f":{port}" if port else "")
    elif target:
        flow = target

    if action_type == "close_alert":
        reason_bit = f" [{reason}]" if reason else ""
        title = f"Close: {subject}{reason_bit}"
        if flow:
            title = f"{title} · {flow}"
    elif action_type == "add_alert_note":
        title = f"Note: {subject}"
        if flow:
            title = f"{title} · {flow}"
    else:
        title = subject
        if flow:
            title = f"{title} · {flow}"
    return title[:180]
