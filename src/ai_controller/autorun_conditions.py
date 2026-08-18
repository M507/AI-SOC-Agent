"""
Autorun condition functions: parsing and prompt context.

A condition string may carry a result limit, e.g. `get_recent_alerts 1` to
pull a single alert per run. The condition output is also rendered into a
context block so the scheduled prompt carries the alert data it triages;
without it the agent has no way to know which alert to work on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger

logger = get_logger("sami.ai_controller.autorun_conditions")

DEFAULT_ALERT_LIMIT = 100
DEFAULT_CASE_LIMIT = 50

# Beyond this the JSON is summarized instead, so a busy SIEM cannot blow up
# the prompt (or the provider's context window) on a scheduled run.
MAX_CONTEXT_CHARS = 12000


@dataclass(frozen=True)
class ConditionSpec:
    """A condition function name plus an optional caller-supplied limit."""

    name: str
    limit: Optional[int] = None
    raw: str = ""

    def alert_limit(self) -> int:
        return self.limit or DEFAULT_ALERT_LIMIT

    def case_limit(self) -> int:
        return self.limit or DEFAULT_CASE_LIMIT


def parse_condition_spec(condition_function: Optional[str]) -> ConditionSpec:
    """
    Parse `get_recent_alerts`, `get_recent_alerts 1`, or `get_recent_alerts limit=1`.

    Unparseable trailing text is left on the name so the generic executor
    fallback keeps receiving the original string.
    """
    raw = (condition_function or "").strip()
    if not raw:
        return ConditionSpec(name="", limit=None, raw="")

    body = raw[4:].strip() if raw.lower().startswith("run ") else raw
    parts = body.split()
    if len(parts) < 2:
        return ConditionSpec(name=body, limit=None, raw=raw)

    candidate = parts[-1]
    if "=" in candidate:
        key, _, value = candidate.partition("=")
        if key.strip().lower() not in {"limit", "max_alerts", "count"}:
            return ConditionSpec(name=body, limit=None, raw=raw)
        candidate = value

    try:
        limit = int(candidate)
    except ValueError:
        return ConditionSpec(name=body, limit=None, raw=raw)
    if limit < 1:
        logger.warning("Ignoring non-positive condition limit in %r", raw)
        return ConditionSpec(name=" ".join(parts[:-1]), limit=None, raw=raw)

    return ConditionSpec(name=" ".join(parts[:-1]), limit=limit, raw=raw)


def _summarize_alerts(output: Dict[str, Any]) -> Dict[str, Any]:
    """Drop per-group examples so only counts and the triage target remain."""
    groups: List[Dict[str, Any]] = []
    for group in output.get("groups") or []:
        if not isinstance(group, dict):
            continue
        groups.append(
            {
                "group_id": group.get("group_id"),
                "title": group.get("title"),
                "primary_severity": group.get("primary_severity"),
                "count": group.get("count"),
                "earliest_created_at": group.get("earliest_created_at"),
            }
        )
    return {
        "total_alerts": output.get("total_alerts"),
        "uninvestigated_alerts": output.get("uninvestigated_alerts"),
        "group_count": output.get("group_count"),
        "suggested_alert_to_triage": output.get("suggested_alert_to_triage"),
        "groups": groups,
    }


def _summarize_cases(output: Dict[str, Any]) -> Dict[str, Any]:
    cases = output.get("cases")
    trimmed = cases[:10] if isinstance(cases, list) else cases
    return {"count": output.get("count"), "cases": trimmed}


def _summarize(output: Any) -> Any:
    if isinstance(output, dict):
        if "uninvestigated_alerts" in output or "groups" in output:
            return _summarize_alerts(output)
        if "cases" in output:
            return _summarize_cases(output)
    if isinstance(output, list):
        return output[:10]
    return output


def build_condition_context(spec: ConditionSpec, output: Any) -> Optional[str]:
    """Render condition output as a prompt preamble, or None when empty."""
    if output is None or isinstance(output, (str, int, float, bool)):
        return None
    if not output:
        return None

    try:
        text = json.dumps(output, indent=2, default=str)
    except (TypeError, ValueError):
        logger.warning("Condition output for %s is not JSON-serializable", spec.name)
        return None

    if len(text) > MAX_CONTEXT_CHARS:
        try:
            text = json.dumps(_summarize(output), indent=2, default=str)
        except (TypeError, ValueError):
            return None
    if len(text) > MAX_CONTEXT_CHARS:
        text = text[:MAX_CONTEXT_CHARS] + "\n... (truncated)"

    return (
        f"The scheduled condition check `{spec.name}` already retrieved the data below. "
        "Use it as the subject of this run instead of asking for alert details.\n\n"
        f"```json\n{text}\n```"
    )
