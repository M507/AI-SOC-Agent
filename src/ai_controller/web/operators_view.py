"""The single console account and the actions it may approve."""

from __future__ import annotations

from typing import Any, Dict, List

from ..approval_queue.catalog import (
    ACTION_CATALOG,
    DETECTION_CATEGORIES,
    ActionSpec,
)

_GROUPS = (
    ("approvals", "Approvals", "not_detection"),
    ("notes", "Notes", "detection"),
)


def approval_groups() -> List[Dict[str, Any]]:
    groups = []
    for group_id, label, kind in _GROUPS:
        if kind == "detection":
            actions = [
                _action(spec) for spec in ACTION_CATALOG if spec.category in DETECTION_CATEGORIES
            ]
            note = (
                "Informational fine-tune, visibility, and runbook notes. "
                "No Approve — Done / Ignore only. Linked GitHub issues show via the GitHub facet."
            )
        else:
            actions = [
                _action(spec) for spec in ACTION_CATALOG if spec.category not in DETECTION_CATEGORIES
            ]
            note = (
                "Closures, alert notes, identity checks, and response actions that wait for "
                "Approve or Yes/No. Host isolation is currently disabled and will not run on Approve."
            )
        groups.append({
            "id": group_id,
            "label": label,
            "note": note,
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
