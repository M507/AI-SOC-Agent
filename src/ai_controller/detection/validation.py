"""Checks that must pass before a review is written to disk.

See documentation/detection-as-code.md for the full gate. Wildcards and
fields that were not on the alert are blocked so a draft cannot widen
the exception past the evidence the analyst saw. A single volatile field
is only a warning: it is a valid exception, but a broad one.

``evaluate_draft_gate`` combines structural checks with regression /
teaching-quality checks used by Send-to-Review's auto-fix loop.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .errors import DetectionError

_VOLATILE = {"source.ip", "destination.ip", "client.ip", "server.ip", "related.ip", "user.name", "source.address"}
VOLATILE_FIELDS = frozenset(_VOLATILE)


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
                raise DetectionError(f"{field} was not on the alert evidence stored with this review.")
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


def _cards_for_gate(revision: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Treat every card as selected for the auto-fix gate."""
    cards = []
    for card in revision.get("exceptions") or []:
        if not isinstance(card, dict):
            continue
        updated = dict(card)
        updated["selected"] = True
        cards.append(updated)
    return cards


def validate_draft_regression(
    revision: Dict[str, Any],
    *,
    diff_text: str = "",
    require_teaching: bool = True,
) -> List[str]:
    """Return blocking regression / quality error strings (empty means pass).

    Soft warnings are not returned here — callers use validate_checked for those.
    """
    errors: List[str] = []
    safe = bool(revision.get("safe_to_except", True))
    cards = [card for card in (revision.get("exceptions") or []) if isinstance(card, dict)]
    if not safe:
        errors.append("Model marked safe_to_except=false.")
    if not cards:
        errors.append("Draft produced no exception cards for this fine-tune.")
    if require_teaching:
        if not str(revision.get("rationale") or "").strip():
            errors.append("Explain the SIEM signal and improvement plan in rationale.")
        plan = revision.get("improvement_plan")
        if not (isinstance(plan, list) and any(str(item).strip() for item in plan)):
            if not str(revision.get("rule_understanding") or "").strip():
                errors.append("Provide improvement_plan or rule_understanding for the analyst.")
    volatile_only = True
    for card in cards:
        entries = [entry for entry in (card.get("entries") or []) if isinstance(entry, dict)]
        if len(entries) != 1:
            volatile_only = False
            break
        field = str(entries[0].get("field") or "").strip()
        if field not in _VOLATILE:
            volatile_only = False
            break
    if cards and volatile_only:
        errors.append(
            "Every exception is a single volatile field (IP/user). Narrow with host/process/path or multi-field ANDs."
        )
    if cards and not str(diff_text or "").strip():
        errors.append("Draft does not change the rule file (empty diff).")
    return errors


def evaluate_draft_gate(
    revision: Dict[str, Any],
    *,
    existing_items: Optional[List[Dict[str, Any]]] = None,
    evidence_fields: Optional[List[str]] = None,
    diff_text: str = "",
    require_teaching: bool = True,
) -> Dict[str, Any]:
    """Run structural + regression checks for one draft revision.

    Returns ``{ok, errors, warnings}``. Does not raise — suitable for the
    Send-to-Review retry loop.
    """
    errors: List[str] = []
    warnings: List[str] = []
    cards = _cards_for_gate(revision)
    try:
        warnings = validate_checked(
            cards,
            existing_items=list(existing_items or []),
            evidence_fields=list(evidence_fields or []),
            enforce_selection=True,
        )
    except DetectionError as exc:
        errors.append(str(exc))
    errors.extend(
        validate_draft_regression(
            revision,
            diff_text=diff_text,
            require_teaching=require_teaching,
        )
    )
    # Dedupe while preserving order
    seen: Set[str] = set()
    unique_errors: List[str] = []
    for item in errors:
        if item in seen:
            continue
        seen.add(item)
        unique_errors.append(item)
    return {
        "ok": not unique_errors,
        "errors": unique_errors,
        "warnings": list(warnings or []),
    }


def evaluate_new_rule_gate(
    revision: Dict[str, Any],
    *,
    coverage_check: Optional[Dict[str, Any]] = None,
    require_teaching: bool = True,
) -> Dict[str, Any]:
    """Validate a new_rule draft revision. Returns ``{ok, errors, warnings}``."""
    errors: List[str] = []
    warnings: List[str] = []
    coverage = coverage_check if isinstance(coverage_check, dict) else {}
    if coverage.get("likely_covered"):
        matches = coverage.get("matching_rules") or []
        hint = ""
        if isinstance(matches, list) and matches:
            first = matches[0] if isinstance(matches[0], dict) else {}
            name = first.get("name") or first.get("rule_id") or ""
            if name:
                hint = f" Matching rule: {name}."
        errors.append(
            "Catalog coverage check says this behavior is likely already covered."
            f"{hint} Use Fine-tune on that rule instead of creating a duplicate."
        )

    safe = bool(revision.get("safe_to_create", True))
    if not safe:
        overlap = str(revision.get("overlapping_rule") or "").strip()
        if overlap:
            errors.append(f"Model marked safe_to_create=false (overlapping: {overlap}).")
        else:
            errors.append("Model marked safe_to_create=false.")

    proposed = revision.get("proposed_rule")
    if not isinstance(proposed, dict):
        errors.append("Draft produced no proposed_rule for this visibility gap.")
        return {"ok": False, "errors": errors, "warnings": warnings}

    rule = proposed.get("rule") if isinstance(proposed.get("rule"), dict) else proposed
    name = str(rule.get("name") or "").strip()
    query = str(rule.get("query") or "").strip()
    severity = str(rule.get("severity") or "").strip().lower()
    rule_type = str(rule.get("type") or "query").strip().lower()
    language = str(rule.get("language") or "kuery").strip().lower()
    index = rule.get("index")
    risk_score = rule.get("risk_score")

    if rule_type and rule_type != "query":
        errors.append(f"Only type=query rules are supported (got {rule_type!r}).")
    if language and language not in {"kuery", "kql", "lucene"}:
        errors.append(f"Unsupported query language {language!r}; use kuery.")
    if not name:
        errors.append("proposed_rule.name is required.")
    if not query:
        errors.append("proposed_rule.query is required.")
    if not severity:
        errors.append("proposed_rule.severity is required.")
    if risk_score is None or risk_score == "":
        errors.append("proposed_rule.risk_score is required.")
    if not isinstance(index, list) or not any(str(item).strip() for item in index):
        errors.append("proposed_rule.index must be a non-empty list.")

    if require_teaching:
        if not str(revision.get("rationale") or "").strip():
            errors.append("Explain why this new rule is needed in rationale.")
        plan = revision.get("improvement_plan")
        if not (isinstance(plan, list) and any(str(item).strip() for item in plan)):
            warnings.append("Consider adding an improvement_plan for the analyst.")

    seen: Set[str] = set()
    unique_errors: List[str] = []
    for item in errors:
        if item in seen:
            continue
        seen.add(item)
        unique_errors.append(item)
    return {
        "ok": not unique_errors,
        "errors": unique_errors,
        "warnings": list(warnings or []),
    }
