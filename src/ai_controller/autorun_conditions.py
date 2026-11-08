"""
Autorun condition functions: parsing and prompt context.

A condition string may carry a result limit and lookback window, e.g.
`get_recent_alerts 1` or `get_recent_alerts hours_back=24 limit=1`.
The condition output is also rendered into a context block so the scheduled
prompt carries the alert data it triages; without it the agent has no way to
know which alert to work on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger

logger = get_logger("sami.ai_controller.autorun_conditions")

DEFAULT_ALERT_LIMIT = 100
DEFAULT_CASE_LIMIT = 50
DEFAULT_ALERT_HOURS_BACK = 1

# Beyond this the JSON is summarized instead, so a busy SIEM cannot blow up
# the prompt (or the provider's context window) on a scheduled run.
MAX_CONTEXT_CHARS = 12000

_LIMIT_KEYS = {"limit", "max_alerts", "count"}
_HOURS_KEYS = {"hours_back", "hours"}


@dataclass(frozen=True)
class ConditionSpec:
    """A condition function name plus optional limit / lookback."""

    name: str
    limit: Optional[int] = None
    hours_back: Optional[int] = None
    raw: str = ""

    def alert_limit(self) -> int:
        return self.limit or DEFAULT_ALERT_LIMIT

    def case_limit(self) -> int:
        return self.limit or DEFAULT_CASE_LIMIT

    def alert_hours_back(self) -> int:
        return self.hours_back or DEFAULT_ALERT_HOURS_BACK


def _parse_positive_int(value: str) -> Optional[int]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 1 else None


def parse_condition_spec(condition_function: Optional[str]) -> ConditionSpec:
    """
    Parse condition strings such as:

    - `get_recent_alerts`
    - `get_recent_alerts 1`
    - `get_recent_alerts limit=1`
    - `get_recent_alerts hours_back=24`
    - `get_recent_alerts hours_back=24 limit=1`
    - `run get_recent_alerts hours_back=24 limit=1`

    Unknown ``key=value`` tokens stay on the name so the generic executor
    fallback still receives them.
    """
    raw = (condition_function or "").strip()
    if not raw:
        return ConditionSpec(name="", limit=None, hours_back=None, raw="")

    body = raw[4:].strip() if raw.lower().startswith("run ") else raw
    parts = body.split()
    if not parts:
        return ConditionSpec(name="", limit=None, hours_back=None, raw=raw)

    name_parts: List[str] = []
    limit: Optional[int] = None
    hours_back: Optional[int] = None

    for part in parts:
        if "=" not in part:
            name_parts.append(part)
            continue
        key, _, value = part.partition("=")
        key_norm = key.strip().lower()
        parsed = _parse_positive_int(value.strip())
        if key_norm in _LIMIT_KEYS and parsed is not None:
            limit = parsed
            continue
        if key_norm in _HOURS_KEYS and parsed is not None:
            hours_back = parsed
            continue
        name_parts.append(part)

    # Trailing bare integer is the items-per-run limit (legacy form).
    if name_parts and limit is None:
        trailing = _parse_positive_int(name_parts[-1])
        if trailing is not None and len(name_parts) >= 2:
            limit = trailing
            name_parts = name_parts[:-1]
        elif trailing is not None and trailing < 1:
            logger.warning("Ignoring non-positive condition limit in %r", raw)
            name_parts = name_parts[:-1]

    return ConditionSpec(
        name=" ".join(name_parts),
        limit=limit,
        hours_back=hours_back,
        raw=raw,
    )


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
