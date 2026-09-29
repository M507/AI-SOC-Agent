"""Ask about one finding. One completion, recorded as detection usage.

This does not open a review and does not write a rule. Checked fields
are required so the model sees the evidence the analyst chose, not the
whole alert. Templates are in prompts.py. See
documentation/detection-as-code.md.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ...llm.registry import get_active_provider
from .errors import DetectionError
from .prompts import ask_system_prompt, build_ask_prompt
from .usage import record_detection_usage


async def ask_about_finding(
    *,
    prompt_id: str,
    alert: Dict[str, Any],
    entries: List[Dict[str, Any]],
    custom_instruction: Optional[str] = None,
) -> Dict[str, Any]:
    if not entries:
        raise DetectionError("Check at least one field before asking.")
    try:
        prompt = build_ask_prompt(
            prompt_id=prompt_id,
            alert=alert,
            entries=entries,
            custom_instruction=custom_instruction,
        )
        system = ask_system_prompt(prompt_id)
    except ValueError as exc:
        raise DetectionError(str(exc)) from exc
    provider = get_active_provider()
    result = await provider.complete(
        prompt,
        system_prompt=system,
        mcp_client=None,
        max_tool_iterations=0,
    )
    record_detection_usage(result, command="detection ask")
    if not getattr(result, "success", False):
        raise DetectionError(getattr(result, "error", None) or "The model call failed.", status_code=502)
    return {
        "prompt_id": prompt_id,
        "answer": getattr(result, "text", "") or "",
        "model": getattr(result, "model", None),
        "provider": getattr(result, "provider", None),
    }
