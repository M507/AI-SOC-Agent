"""The single console account and the actions it may approve."""

from __future__ import annotations

from typing import Any, Dict, List

from ..approval_queue.catalog import (
    ACTION_CATALOG,
    ActionSpec,
)

_GROUPS = (
    ("closures", "Closures", "closures"),
    ("alert_notes", "Alert notes", "alert_notes"),
    ("questions", "Questions", "questions"),
    ("response", "Response", "response"),
    ("fine_tune", "Fine-tune", "fine_tune"),
    ("visibility", "Visibility", "visibility"),
    ("runbooks", "Runbooks", "runbooks"),
)

_GROUP_NOTES = {
    "closures": "Close alert / close case — Approve writes the close.",
    "alert_notes": "Add alert note — Approve writes the SIEM comment (also auto-approved with a matching Close).",
    "questions": "Is this you? — Yes/No verification cards.",
    "response": (
        "Containment and escalation (isolate, kill process, forensics, escalate, open case, …). "
        "Host isolation is currently disabled and will not run on Approve."
    ),
    "fine_tune": "Informational detection-tuning suggestions. No Approve — Done / Ignore only.",
    "visibility": "Informational visibility / coverage gaps. No Approve — Done / Ignore only.",
    "runbooks": "Missing case-playbook notes. No Approve — Done / Ignore / Create runbook.",
}


def approval_groups() -> List[Dict[str, Any]]:
    groups = []
    for group_id, label, tab in _GROUPS:
        actions = [_action(spec) for spec in ACTION_CATALOG if spec.queue_tab == tab]
        groups.append({
            "id": group_id,
            "label": label,
            "note": _GROUP_NOTES.get(tab, ""),
            "actions": actions,
        })
    return groups


def _action(spec: ActionSpec) -> Dict[str, str]:
    risk = (spec.risk or "").strip()
    return {
        "label": spec.label,
        "description": spec.description,
        "risk": risk[:1].upper() + risk[1:] if risk else "",
    }
