"""Record Detection as Code model calls on the existing usage ledger.

Ask, Draft, and Ask for changes each spend one completion. They are
tagged session_type=detection so they stay separate from SOC chat in the
cost ledger. A ledger write failure is logged and swallowed: the analyst
already has the model answer, and losing the usage row must not fail
the review. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..usage import record_model_round

logger = logging.getLogger("sami.detection.usage")


def record_detection_usage(
    result: Any,
    *,
    command: str,
    request_id: Optional[str] = None,
) -> None:
    """Write one ledger row per model round. A write failure does not fail the draft."""
    usage: Dict[str, Any] = getattr(result, "usage", None) or {}
    rounds = usage.get("rounds") or []
    if not rounds:
        rounds = [usage] if usage else [{"usage_reported": False}]
    for round_usage in rounds:
        try:
            record_model_round(
                tokens=round_usage if isinstance(round_usage, dict) else {},
                provider=getattr(result, "provider", None),
                configured_model=usage.get("configured_model") or getattr(result, "model", None),
                session_type="detection",
                command=command,
                request_id=request_id,
            )
        except Exception as exc:
            logger.exception("Could not record detection usage: %s", exc)
