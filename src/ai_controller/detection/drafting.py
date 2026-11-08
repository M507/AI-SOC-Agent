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
from .prompts import DRAFT_SYSTEM, build_draft_prompt
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
