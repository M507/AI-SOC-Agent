"""One structured completion for Draft or Revise. No MCP tools.

The model is not given tools, so a draft cannot close alerts or edit
files. Medium and high confidence cards start selected; low confidence
stays off so the analyst has to opt in. The system prompt and JSON
contract live in prompts.py. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

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


def normalize_suggestions(raw: Dict[str, Any]) -> Dict[str, Any]:
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
        name = str(item.get("name") or "").strip() or " / ".join(f"{entry['field']}={entry['value']}" for entry in entries[:3])
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
    }


async def complete_draft(
    *,
    rule_file: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    feedback: str | None = None,
    previous: Dict[str, Any] | None = None,
    request_id: str | None = None,
    command: str = "detection draft",
) -> Dict[str, Any]:
    provider = get_active_provider()
    prompt = build_draft_prompt(
        rule_file=rule_file,
        alerts=alerts,
        feedback=feedback,
        previous=previous,
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
