"""Checks that must pass before a review is written to disk.

See documentation/detection-as-code.md for the full gate. Wildcards and
fields that were not on the finding are blocked so a draft cannot widen
the exception past the evidence the analyst saw. A single volatile field
is only a warning: it is a valid exception, but a broad one.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set, Tuple

from .errors import DetectionError

_VOLATILE = {"source.ip", "destination.ip", "client.ip", "server.ip", "related.ip", "user.name", "source.address"}


def _pair(entry: Dict[str, Any]) -> Tuple[str, str]:
    return (str(entry.get("field") or "").strip(), str(entry.get("value") if entry.get("value") is not None else "").strip())


def _signature(entries: Iterable[Dict[str, Any]]) -> Tuple[Tuple[str, str], ...]:
    pairs = [_pair(entry) for entry in entries]
    return tuple(sorted(pairs))


def existing_signatures(exception_items: List[Dict[str, Any]]) -> Set[Tuple[Tuple[str, str], ...]]:
    found: Set[Tuple[Tuple[str, str], ...]] = set()
    for item in exception_items or []:
        if not isinstance(item, dict):
            continue
        entries = item.get("entries") if isinstance(item.get("entries"), list) else []
        signature = _signature(entry for entry in entries if isinstance(entry, dict))
        if signature:
            found.add(signature)
    return found


def validate_checked(
    cards: List[Dict[str, Any]],
    *,
    existing_items: List[Dict[str, Any]],
    evidence_fields: List[str],
    enforce_selection: bool = True,
) -> List[str]:
    """Return non-blocking breadth warnings. Raise DetectionError on a blocking problem.

    The Review page previews warnings with enforce_selection=False. An empty
    selection is expected there until the analyst checks a card. Implement
    keeps the default and refuses to write with nothing selected.
    A missing ``selected`` key counts as checked, matching the checkbox
    (``selected !== false``) so older cards are not dropped by accident.
    """
    checked = [card for card in cards if isinstance(card, dict) and card.get("selected") is not False]
    if not checked:
        if enforce_selection:
            raise DetectionError("Select at least one condition to implement.")
        return []
    warnings: List[str] = []
    seen: Set[Tuple[Tuple[str, str], ...]] = set()
    already = existing_signatures(existing_items)
    evidence = {str(field).strip() for field in evidence_fields or [] if str(field).strip()}
    for card in checked:
        entries = card.get("entries") if isinstance(card.get("entries"), list) else []
        if not entries:
            raise DetectionError(f"Exception {card.get('name') or '(unnamed)'} has no fields.")
        clean: List[Dict[str, str]] = []
        allow_wild = bool(card.get("allow_wildcard"))
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            field, value = _pair(entry)
            if not field or not value:
                raise DetectionError("Each condition needs a non-empty field and value.")
            if not allow_wild and ("*" in value or "?" in value):
                raise DetectionError(f"{field} uses a wildcard. Allow it on that card or remove it.")
            if evidence and field not in evidence:
                raise DetectionError(f"{field} was not on the finding evidence stored with this review.")
            clean.append({"field": field, "value": value})
        signature = _signature(clean)
        if signature in already:
            raise DetectionError(f"Exception {card.get('name') or signature} is already on the rule.")
        if signature in seen:
            raise DetectionError("Two checked conditions are the same.")
        seen.add(signature)
        if len(clean) == 1 and clean[0]["field"] in _VOLATILE:
            warnings.append(f"{clean[0]['field']} is a single volatile field. Confirm it is narrow enough.")
    return warnings
