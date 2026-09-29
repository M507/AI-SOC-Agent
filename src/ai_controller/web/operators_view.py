"""The single console account and the actions it may approve."""

from __future__ import annotations

from typing import Any, Dict, List

from ..approval_queue.catalog import (
    ACTION_CATALOG,
    DETECTION_CATEGORIES,
    SOC_CATEGORIES,
    ActionSpec,
)

_GROUPS = (
    ("soc", "SOC", SOC_CATEGORIES),
    ("detection", "Detection engineering", DETECTION_CATEGORIES),
    ("engineering", "Engineering", DETECTION_CATEGORIES),
)


def approval_groups() -> List[Dict[str, Any]]:
    groups = []
    for group_id, label, categories in _GROUPS:
        actions = [_action(spec) for spec in ACTION_CATALOG if spec.category in categories]
        note = ""
        if group_id == "engineering":
            note = "These notes show on Engineering when they are linked to a GitHub issue."
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
