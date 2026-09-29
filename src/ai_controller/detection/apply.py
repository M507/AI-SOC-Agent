"""Build exception items and write them into the configured rules folder.

Only cards with selected not False are written. Field-built cards start
unselected, so calling this before the analyst checks a box would append
nothing; validation rejects that earlier. The item shape is a single
included match so it stays compatible with the Elastic exception item
the rule file already uses. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .rules_store import apply_additions, apply_disable


def _item_id(rule_id: str, entries: List[Dict[str, str]]) -> str:
    blob = "|".join(f"{entry['field']}={entry['value']}" for entry in entries)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:10]
    return f"sami-{rule_id[:8]}-{digest}"


def exception_item(rule_id: str, card: Dict[str, Any]) -> Dict[str, Any]:
    entries = [
        {
            "field": str(entry.get("field") or "").strip(),
            "operator": "included",
            "type": "match",
            "value": str(entry.get("value")),
        }
        for entry in (card.get("entries") or [])
        if isinstance(entry, dict) and str(entry.get("field") or "").strip()
    ]
    name = str(card.get("name") or "").strip() or " / ".join(
        f"{entry['field']}={entry['value']}" for entry in entries[:3]
    )
    return {
        "item_id": _item_id(rule_id, [{"field": entry["field"], "value": str(entry["value"])} for entry in entries]),
        "list_id": f"sami-{rule_id[:8]}-exceptions",
        "type": "simple",
        "name": name[:120],
        "description": "Created by SamiGPT Detection as Code",
        "namespace_type": "single",
        "entries": entries,
    }


def write_exceptions(path, data, cards, expected_sha256: str, rule_id: str) -> Dict[str, Any]:
    checked = [card for card in cards if isinstance(card, dict) and card.get("selected") is not False]
    additions = [exception_item(rule_id, card) for card in checked]
    result = apply_additions(path, data, additions, expected_sha256)
    result["exception_items"] = additions
    return result


def write_disabled(path, data, expected_sha256: str) -> Dict[str, Any]:
    return apply_disable(path, data, expected_sha256)
