"""One structured completion for Draft or Revise. No MCP tools.

The model is not given tools, so a draft cannot close alerts or edit
files. Medium and high confidence cards start selected; low confidence
stays off so the analyst has to opt in. The system prompt and JSON
contract live in prompts.py. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from ...llm.registry import get_active_provider
from .errors import DetectionError
from .prompts import (
    DRAFT_SYSTEM,
    NEW_RULE_DRAFT_SYSTEM,
    build_draft_prompt,
    build_new_rule_draft_prompt,
)
from .usage import record_detection_usage


def extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = (text or "").strip()
    if not cleaned:
        raise DetectionError("The model returned an empty response.", status_code=502)
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise DetectionError("Could not parse JSON from the model response.", status_code=502) from exc
        if isinstance(parsed, dict):
            return parsed
    raise DetectionError("Could not parse JSON from the model response.", status_code=502)


def _normalize_siem_context(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    sources = raw.get("data_sources")
    if not isinstance(sources, list):
        sources = []
    return {
        "platform": str(raw.get("platform") or "elastic").strip() or "elastic",
        "rule_type": str(raw.get("rule_type") or "").strip(),
        "signal_summary": str(raw.get("signal_summary") or "").strip(),
        "data_sources": [str(item).strip() for item in sources if str(item).strip()][:12],
    }


def _normalize_improvement_plan(raw: Any) -> List[str]:
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()][:8]


def normalize_suggestions(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize model JSON. New teaching fields are optional for older responses."""
    exceptions: List[Dict[str, Any]] = []
    for item in raw.get("exceptions") or []:
        if not isinstance(item, dict):
            continue
        entries = []
        for entry in item.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            field = str(entry.get("field") or "").strip()
            value = entry.get("value")
            if not field or value in (None, ""):
                continue
            entries.append({"field": field, "value": str(value)})
        if not entries:
            continue
        name = str(item.get("name") or "").strip() or " / ".join(
            f"{entry['field']}={entry['value']}" for entry in entries[:3]
        )
        confidence = str(item.get("confidence") or "medium").strip().lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"
        safe = bool(raw.get("safe_to_except", True))
        selected = confidence in {"medium", "high"} and safe
        exceptions.append(
            {
                "name": name[:120],
                "confidence": confidence,
                "entries": entries,
                "selected": selected,
                "allow_wildcard": False,
            }
        )
    return {
        "rationale": str(raw.get("rationale") or "").strip(),
        "safe_to_except": bool(raw.get("safe_to_except", bool(exceptions))),
        "exceptions": exceptions,
        "notes": str(raw.get("notes") or "").strip(),
        "siem_context": _normalize_siem_context(raw.get("siem_context")),
        "rule_understanding": str(raw.get("rule_understanding") or "").strip(),
        "improvement_plan": _normalize_improvement_plan(raw.get("improvement_plan")),
    }


async def complete_draft(
    *,
    rule_file: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    feedback: str | None = None,
    previous: Dict[str, Any] | None = None,
    suggestion: str | None = None,
    suggestion_title: str | None = None,
    cluster_id: str | None = None,
    request_id: str | None = None,
    command: str = "detection draft",
    analyst_instructions: str | None = None,
) -> Dict[str, Any]:
    """Call the active LLM once and return normalized exception suggestions."""
    provider = get_active_provider()
    prompt = build_draft_prompt(
        rule_file=rule_file,
        alerts=alerts,
        feedback=feedback,
        previous=previous,
        suggestion=suggestion,
        suggestion_title=suggestion_title,
        cluster_id=cluster_id,
        analyst_instructions=analyst_instructions,
    )
    result = await provider.complete(
        prompt,
        system_prompt=DRAFT_SYSTEM,
        mcp_client=None,
        max_tool_iterations=0,
    )
    record_detection_usage(result, command=command, request_id=request_id)
    if not getattr(result, "success", False):
        raise DetectionError(getattr(result, "error", None) or "The model call failed.", status_code=502)
    return normalize_suggestions(extract_json_object(getattr(result, "text", "") or ""))


def normalize_new_rule_suggestions(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize model JSON for a net-new query rule draft."""
    proposed = raw.get("proposed_rule")
    rule: Dict[str, Any] = {}
    if isinstance(proposed, dict):
        inner = proposed.get("rule") if isinstance(proposed.get("rule"), dict) else proposed
        if isinstance(inner, dict):
            index = inner.get("index")
            if isinstance(index, str) and index.strip():
                index = [index.strip()]
            if not isinstance(index, list):
                index = []
            tags = inner.get("tags") if isinstance(inner.get("tags"), list) else []
            rule = {
                "name": str(inner.get("name") or "").strip(),
                "description": str(inner.get("description") or "").strip(),
                "severity": str(inner.get("severity") or "medium").strip().lower() or "medium",
                "risk_score": inner.get("risk_score") if inner.get("risk_score") is not None else 47,
                "type": "query",
                "language": str(inner.get("language") or "kuery").strip() or "kuery",
                "query": str(inner.get("query") or "").strip(),
                "index": [str(item).strip() for item in index if str(item).strip()] or ["logs-*"],
                "enabled": True,
                "tags": [str(item).strip() for item in tags if str(item).strip()][:12],
            }
    safe = bool(raw.get("safe_to_create", bool(rule.get("query"))))
    return {
        "rationale": str(raw.get("rationale") or "").strip(),
        "safe_to_create": safe,
        "overlapping_rule": str(raw.get("overlapping_rule") or "").strip(),
        "notes": str(raw.get("notes") or "").strip(),
        "improvement_plan": _normalize_improvement_plan(raw.get("improvement_plan")),
        "proposed_rule": rule if rule.get("query") or rule.get("name") else None,
        "exceptions": [],
    }


async def complete_new_rule_draft(
    *,
    suggestion: str | None = None,
    suggestion_title: str | None = None,
    coverage_check: Dict[str, Any] | None = None,
    source: str | None = None,
    alerts: List[Dict[str, Any]] | None = None,
    feedback: str | None = None,
    previous: Dict[str, Any] | None = None,
    cluster_id: str | None = None,
    request_id: str | None = None,
    command: str = "detection new_rule draft",
    analyst_instructions: str | None = None,
) -> Dict[str, Any]:
    """Call the active LLM once and return a normalized new-rule draft."""
    provider = get_active_provider()
    prompt = build_new_rule_draft_prompt(
        suggestion=suggestion or "",
        suggestion_title=suggestion_title or "",
        coverage_check=coverage_check,
        source=source or "",
        alerts=alerts or [],
        feedback=feedback,
        previous=previous,
        analyst_instructions=analyst_instructions,
        cluster_id=cluster_id,
    )
    result = await provider.complete(
        prompt,
        system_prompt=NEW_RULE_DRAFT_SYSTEM,
        mcp_client=None,
        max_tool_iterations=0,
    )
    record_detection_usage(result, command=command, request_id=request_id)
    if not getattr(result, "success", False):
        raise DetectionError(getattr(result, "error", None) or "The model call failed.", status_code=502)
    return normalize_new_rule_suggestions(extract_json_object(getattr(result, "text", "") or ""))
