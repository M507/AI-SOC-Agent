"""Helpers for masking secrets in API responses and config round-trips."""

from __future__ import annotations

from typing import Any, Dict, Optional

MASKED_PLACEHOLDER = "••••••••"
_MASK_MARKERS = ("...", "••", "****")
_SECRET_KEYS = {
    "api_key",
    "api_token",
    "password",
    "secret",
    "session_secret",
    "admin_secret",
}


def mask_secret(value: Optional[str]) -> str:
    """Return a display-safe version of a secret."""
    if not value:
        return ""
    if len(value) < 8:
        return MASKED_PLACEHOLDER
    return f"{value[:4]}...{value[-4:]}"


def is_masked_secret(value: Optional[str]) -> bool:
    """True when the value looks like a masked placeholder, not a real secret."""
    if value is None:
        return True
    stripped = value.strip()
    if not stripped:
        return True
    if stripped == MASKED_PLACEHOLDER:
        return True
    return any(marker in stripped for marker in _MASK_MARKERS)


def mask_mapping(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of `data` with known secret fields masked."""
    masked: Dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            masked[key] = mask_mapping(value)
        elif isinstance(value, list):
            masked[key] = [
                mask_mapping(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str) and key.lower() in _SECRET_KEYS:
            masked[key] = mask_secret(value)
        else:
            masked[key] = value
    return masked


def merge_secrets(
    incoming: Dict[str, Any],
    existing: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Merge user-submitted settings with stored settings.

    If the user left a secret blank or sent back a masked value, keep the
    previously stored secret so round-trips through the UI do not wipe keys.
    """
    existing = existing or {}
    merged: Dict[str, Any] = dict(existing)
    for key, value in incoming.items():
        if isinstance(value, dict):
            merged[key] = merge_secrets(value, existing.get(key) if isinstance(existing.get(key), dict) else {})
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            existing_list = existing.get(key) if isinstance(existing.get(key), list) else []
            existing_by_id = {
                item.get("id"): item
                for item in existing_list
                if isinstance(item, dict) and item.get("id")
            }
            merged[key] = [
                merge_secrets(item, existing_by_id.get(item.get("id"), {}))
                for item in value
            ]
        elif isinstance(value, str) and key.lower() in _SECRET_KEYS and is_masked_secret(value):
            if key in existing:
                merged[key] = existing[key]
        else:
            merged[key] = value
    return merged
