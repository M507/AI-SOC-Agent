"""Saved Detection as Code settings. The rules folder lives in config.json.

Resolution order is the env var, then this section, then the built-in
default path. An empty saved path is valid and means "use the default".
A non-empty path must already be a directory so a typo cannot point the
indexer at nothing. Hours are clamped so a bad value cannot request an
unbounded Elastic search. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

from ...core.config_storage import get_section, update_raw_section
from ..approval_queue.lab_rules import DEFAULT_RULES_DIR, clear_index_cache
from .errors import DetectionError

SECTION = "detection"
DEFAULT_FINDINGS_HOURS = 168
DEFAULT_MATCH_HOURS = 24 * 90
MAX_HOURS = 24 * 90


def _clamp_hours(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(number, MAX_HOURS))


def stored_settings() -> Dict[str, Any]:
    raw = get_section(SECTION, {}) or {}
    return {
        "rules_dir": str(raw.get("rules_dir") or "").strip(),
        "findings_hours": _clamp_hours(raw.get("findings_hours"), DEFAULT_FINDINGS_HOURS),
        "match_hours": _clamp_hours(raw.get("match_hours"), DEFAULT_MATCH_HOURS),
    }


def env_rules_dir() -> str:
    return os.environ.get("SAMI_LAB_RULES_DIR", "").strip()


def effective_rules_dir(default: Path) -> Path:
    """Env override, then the saved folder, then the built-in default path."""
    env = env_rules_dir()
    if env:
        return Path(env)
    stored = stored_settings()["rules_dir"]
    if stored:
        return Path(stored)
    return default


def normalize_rules_dir(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    path = Path(text).expanduser()
    try:
        path = path.resolve()
    except OSError as exc:
        raise DetectionError(f"Rules folder is not a usable path: {exc}") from exc
    if not path.is_dir():
        raise DetectionError(f"Rules folder does not exist: {path}")
    return str(path)


def save_settings(
    *,
    rules_dir: str,
    findings_hours: Any = None,
    match_hours: Any = None,
) -> Dict[str, Any]:
    current = stored_settings()
    payload = {
        "rules_dir": normalize_rules_dir(rules_dir),
        "findings_hours": _clamp_hours(
            current["findings_hours"] if findings_hours is None else findings_hours,
            DEFAULT_FINDINGS_HOURS,
        ),
        "match_hours": _clamp_hours(
            current["match_hours"] if match_hours is None else match_hours,
            DEFAULT_MATCH_HOURS,
        ),
    }
    update_raw_section(SECTION, payload)
    clear_index_cache()
    return public_settings()


def public_settings(default_rules_dir: Path | None = None) -> Dict[str, Any]:
    """Saved path stays blank when cleared. effective_path still names the folder in use."""
    stored = stored_settings()
    env = env_rules_dir()
    fallback = DEFAULT_RULES_DIR if default_rules_dir is None else default_rules_dir
    effective = Path(env) if env else (Path(stored["rules_dir"]) if stored["rules_dir"] else fallback)
    exists = bool(effective and effective.is_dir())
    source = "env" if env else ("config" if stored["rules_dir"] else "default")
    return {
        "rules_dir": stored["rules_dir"],
        "effective_path": str(effective) if effective else "",
        "configured": exists,
        "source": source,
        "env_override": bool(env),
        "findings_hours": stored["findings_hours"],
        "match_hours": stored["match_hours"],
    }
