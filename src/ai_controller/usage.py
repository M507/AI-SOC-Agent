"""Permanent token ledger and model price table.

Token counts live in /var/lib/servee/usage.jsonl (append-only). Dollar amounts
are computed from /var/lib/servee/pricing.json when they are shown, so a rate
change updates every past and future figure without rewriting history.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.logging import get_logger

logger = get_logger("sami.ai_controller.usage")

_LOCK = threading.Lock()
_DEFAULT_USAGE_DIR = Path(os.getenv("SAMIGPT_USAGE_DIR", "/var/lib/servee"))
_BUNDLED_PRICING = Path(__file__).resolve().parent / "pricing.default.json"


def usage_dir() -> Path:
    return Path(os.getenv("SAMIGPT_USAGE_DIR", str(_DEFAULT_USAGE_DIR)))


def usage_path() -> Path:
    return usage_dir() / "usage.jsonl"


def pricing_path() -> Path:
    return usage_dir() / "pricing.json"


def normalize_model_key(name: Optional[str]) -> str:
    raw = (name or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "", raw)


def _empty_tokens() -> Dict[str, int]:
    return {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 0,
    }


def parse_usage_payload(payload: Any) -> Dict[str, Any]:
    """Read OpenAI-style and Open WebUI Responses usage into one shape."""
    tokens = _empty_tokens()
    reported_model = ""
    found = False
    if not isinstance(payload, dict):
        return {**tokens, "usage_reported": False, "reported_model": reported_model}

    reported_model = str(payload.get("model") or "").strip()
    candidates: List[Dict[str, Any]] = []
    usage = payload.get("usage")
    if isinstance(usage, dict):
        candidates.append(usage)
    response = payload.get("response")
    if isinstance(response, dict):
        if response.get("model") and not reported_model:
            reported_model = str(response.get("model") or "").strip()
        nested = response.get("usage")
        if isinstance(nested, dict):
            candidates.append(nested)

    for usage in candidates:
        input_tokens = _int(
            usage.get("input_tokens")
            or usage.get("prompt_tokens")
            or usage.get("prompt_token_count")
        )
        output_tokens = _int(
            usage.get("output_tokens")
            or usage.get("completion_tokens")
            or usage.get("completion_token_count")
        )
        details = usage.get("input_tokens_details") or usage.get("prompt_tokens_details") or {}
        if not isinstance(details, dict):
            details = {}
        cached = _int(
            details.get("cached_tokens")
            or details.get("cache_read_tokens")
            or usage.get("cached_tokens")
            or usage.get("cache_read_input_tokens")
            or usage.get("prompt_cache_hit_tokens")
        )
        cache_write = _int(
            details.get("cache_write_tokens")
            or usage.get("cache_creation_input_tokens")
            or usage.get("cache_write_tokens")
        )
        if input_tokens or output_tokens or cached or cache_write:
            found = True
        tokens["input_tokens"] += input_tokens
        tokens["cached_input_tokens"] += cached
        tokens["cache_write_tokens"] += cache_write
        tokens["output_tokens"] += output_tokens

    if tokens["cached_input_tokens"] > tokens["input_tokens"] > 0:
        tokens["cached_input_tokens"] = tokens["input_tokens"]
    return {**tokens, "usage_reported": found, "reported_model": reported_model}


def merge_usage(parts: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total = {**_empty_tokens(), "usage_reported": False, "reported_model": "", "rounds": []}
    rounds: List[Dict[str, Any]] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        parsed = parse_usage_payload(part) if "usage" in part or "response" in part else {
            **_empty_tokens(),
            **{key: _int(part.get(key)) for key in _empty_tokens()},
            "usage_reported": bool(part.get("usage_reported")),
            "reported_model": str(part.get("reported_model") or ""),
        }
        if parsed.get("usage_reported"):
            total["usage_reported"] = True
        if parsed.get("reported_model") and not total["reported_model"]:
            total["reported_model"] = parsed["reported_model"]
        for key in _empty_tokens():
            total[key] += _int(parsed.get(key))
        rounds.append({key: _int(parsed.get(key)) for key in _empty_tokens()} | {
            "usage_reported": bool(parsed.get("usage_reported")),
            "reported_model": parsed.get("reported_model") or "",
        })
    total["rounds"] = rounds
    if total["cached_input_tokens"] > total["input_tokens"] > 0:
        total["cached_input_tokens"] = total["input_tokens"]
    return total


def cost_for_tokens(tokens: Dict[str, Any], rates: Optional[Dict[str, Any]]) -> Optional[float]:
    if not rates or not tokens.get("usage_reported"):
        return None
    input_tokens = _int(tokens.get("input_tokens"))
    cached = min(_int(tokens.get("cached_input_tokens")), input_tokens)
    uncached = max(0, input_tokens - cached)
    cache_write = _int(tokens.get("cache_write_tokens"))
    output_tokens = _int(tokens.get("output_tokens"))
    input_rate = _float(rates.get("input"))
    cache_read_rate = _float(rates.get("cache_read"))
    cache_write_rate = _float(rates.get("cache_write", rates.get("input")))
    output_rate = _float(rates.get("output"))
    dollars = (
        uncached * input_rate
        + cached * cache_read_rate
        + cache_write * cache_write_rate
        + output_tokens * output_rate
    ) / 1_000_000
    return round(dollars, 6)


def default_pricing() -> Dict[str, Any]:
    if _BUNDLED_PRICING.exists():
        with open(_BUNDLED_PRICING, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return {
        "currency": "USD",
        "unit": "per_million_tokens",
        "models": {
            "auto": {
                "name": "Auto",
                "provider": "Cursor",
                "input": 2.5,
                "cache_write": 2.5,
                "cache_read": 0.35,
                "output": 10.0,
                "estimate": True,
            }
        },
    }


def ensure_pricing_file() -> Path:
    path = pricing_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        source = _BUNDLED_PRICING if _BUNDLED_PRICING.exists() else None
        if source:
            shutil.copyfile(source, path)
        else:
            path.write_text(json.dumps(default_pricing(), indent=2) + "\n", encoding="utf-8")
        logger.info("Wrote default model prices to %s", path)
    return path


def load_pricing() -> Dict[str, Any]:
    try:
        ensure_pricing_file()
        with open(pricing_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or not isinstance(data.get("models"), dict):
            raise ValueError("pricing.json must contain a models object")
        return data
    except Exception as exc:
        logger.warning("Could not read pricing file %s: %s", pricing_path(), exc)
        raise


def save_pricing(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("models"), dict):
        raise ValueError("pricing.json must contain a models object")
    path = pricing_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)
    return data


def match_rates(pricing: Dict[str, Any], *names: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    models = pricing.get("models") if isinstance(pricing, dict) else {}
    if not isinstance(models, dict):
        return None, None
    indexed = {normalize_model_key(key): (key, value) for key, value in models.items()}
    for name in names:
        key = normalize_model_key(name)
        if key and key in indexed:
            stored_key, rates = indexed[key]
            if isinstance(rates, dict):
                return stored_key, rates
    return None, None


def price_tokens(tokens: Dict[str, Any], *model_names: Optional[str]) -> Dict[str, Any]:
    try:
        pricing = load_pricing()
        pricing_ok = True
        pricing_error = None
    except Exception as exc:
        pricing = default_pricing()
        pricing_ok = False
        pricing_error = str(exc)
    matched, rates = match_rates(pricing, *model_names)
    cost = cost_for_tokens(tokens, rates) if pricing_ok else None
    return {
        "model_key": matched,
        "rates": rates,
        "cost_usd": cost,
        "priced": cost is not None,
        "pricing_ok": pricing_ok,
        "pricing_error": pricing_error,
        "uncached_input_tokens": max(
            0, _int(tokens.get("input_tokens")) - min(_int(tokens.get("cached_input_tokens")), _int(tokens.get("input_tokens")))
        ),
    }


def append_usage(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Append one model-round row. Failures are logged; they do not raise."""
    row = dict(record)
    row.setdefault("at", datetime.now(timezone.utc).isoformat())
    for key in _empty_tokens():
        row[key] = _int(row.get(key))
    row["usage_reported"] = bool(row.get("usage_reported"))
    path = usage_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, separators=(",", ":"), ensure_ascii=True)
        with _LOCK:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return row
    except Exception as exc:
        logger.exception("Could not append usage row to %s: %s", path, exc)
        return None


def record_model_round(
    *,
    tokens: Dict[str, Any],
    provider: Optional[str],
    configured_model: Optional[str],
    session_id: Optional[str] = None,
    entry_id: Optional[str] = None,
    session_type: Optional[str] = None,
    session_name: Optional[str] = None,
    autorun_id: Optional[str] = None,
    autorun_name: Optional[str] = None,
    command: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    reported = str(tokens.get("reported_model") or configured_model or "")
    return append_usage(
        {
            "session_id": session_id,
            "entry_id": entry_id,
            "session_type": session_type,
            "session_name": session_name,
            "autorun_id": autorun_id,
            "autorun_name": autorun_name,
            "command": _clip(command, 160),
            "provider": provider,
            "model": normalize_model_key(configured_model) or "unknown",
            "reported_model": reported,
            "input_tokens": tokens.get("input_tokens"),
            "cached_input_tokens": tokens.get("cached_input_tokens"),
            "cache_write_tokens": tokens.get("cache_write_tokens"),
            "output_tokens": tokens.get("output_tokens"),
            "usage_reported": tokens.get("usage_reported"),
        }
    )


def read_usage() -> List[Dict[str, Any]]:
    path = usage_path()
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed usage line")
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def format_cost(amount: Optional[float]) -> Optional[str]:
    if amount is None:
        return None
    if amount == 0:
        return "$0.00"
    if abs(amount) < 0.01:
        return f"${amount:.6f}".rstrip("0").rstrip(".")
    return f"${amount:.4f}".rstrip("0").rstrip(".") if amount < 1 else f"${amount:.2f}"


def usage_footer(tokens: Dict[str, Any], priced: Dict[str, Any], saved: bool = True) -> str:
    if not tokens.get("usage_reported"):
        return "Tokens: usage not reported"
    parts = [
        f"Tokens in {_int(tokens.get('input_tokens')):,}",
        f"cached {_int(tokens.get('cached_input_tokens')):,}",
        f"out {_int(tokens.get('output_tokens')):,}",
    ]
    if priced.get("priced"):
        parts.append(format_cost(priced.get("cost_usd")) or "$0.00")
    elif not priced.get("pricing_ok"):
        parts.append("pricing file unreadable")
    else:
        parts.append("unpriced")
    if not saved:
        parts.append("usage not saved")
    return " · ".join(parts)


def dashboard() -> Dict[str, Any]:
    try:
        pricing = load_pricing()
        pricing_ok = True
        pricing_error = None
    except Exception as exc:
        pricing = default_pricing()
        pricing_ok = False
        pricing_error = str(exc)
    rows = [_decorate(row, pricing, pricing_ok) for row in read_usage()]
    now = datetime.now(timezone.utc)
    windows = {
        "all": None,
        "today": now.replace(hour=0, minute=0, second=0, microsecond=0),
        "7d": now - timedelta(days=7),
        "30d": now - timedelta(days=30),
    }
    overview = {name: _summarize(_since(rows, start)) for name, start in windows.items()}
    return {
        "success": True,
        "pricing_ok": pricing_ok,
        "pricing_error": pricing_error,
        "overview": overview,
        "sessions": _group_sessions(rows),
        "models": _group_models(rows),
        "calls": list(reversed(rows[-500:])),
        "rates": pricing,
        "unpriced_calls": sum(1 for row in rows if row.get("usage_reported") and not row.get("priced")),
        "unreported_calls": sum(1 for row in rows if not row.get("usage_reported")),
        "total_calls": len(rows),
    }


def _decorate(row: Dict[str, Any], pricing: Dict[str, Any], pricing_ok: bool) -> Dict[str, Any]:
    tokens = {
        **{key: _int(row.get(key)) for key in _empty_tokens()},
        "usage_reported": bool(row.get("usage_reported")),
    }
    matched, rates = match_rates(pricing, row.get("reported_model"), row.get("model"))
    cost = cost_for_tokens(tokens, rates) if pricing_ok else None
    decorated = dict(row)
    decorated.update(tokens)
    decorated["model_key"] = matched
    decorated["rates"] = rates
    decorated["cost_usd"] = cost
    decorated["priced"] = cost is not None
    decorated["cost_label"] = format_cost(cost) if tokens["usage_reported"] else None
    decorated["uncached_input_tokens"] = max(0, tokens["input_tokens"] - min(tokens["cached_input_tokens"], tokens["input_tokens"]))
    return decorated


def _since(rows: List[Dict[str, Any]], start: Optional[datetime]) -> List[Dict[str, Any]]:
    if start is None:
        return rows
    kept = []
    for row in rows:
        stamp = _parse_time(row.get("at"))
        if stamp is None or stamp >= start:
            kept.append(row)
    return kept


def _summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    tokens = _empty_tokens()
    cost = 0.0
    priced = False
    reported = 0
    for row in rows:
        for key in tokens:
            tokens[key] += _int(row.get(key))
        if row.get("usage_reported"):
            reported += 1
        if row.get("priced") and row.get("cost_usd") is not None:
            cost += float(row["cost_usd"])
            priced = True
    return {
        "calls": len(rows),
        "reported_calls": reported,
        "unreported_calls": len(rows) - reported,
        **tokens,
        "cost_usd": round(cost, 6) if priced else None,
        "cost_label": format_cost(cost) if priced else None,
    }


def _group_sessions(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("session_id") or row.get("autorun_id") or "unknown")
        bucket = grouped.setdefault(
            key,
            {
                "session_id": row.get("session_id"),
                "session_name": row.get("session_name") or "Untitled session",
                "session_type": row.get("session_type") or "manual",
                "autorun_id": row.get("autorun_id"),
                "autorun_name": row.get("autorun_name"),
                "first_at": row.get("at"),
                "last_at": row.get("at"),
                "rows": [],
            },
        )
        bucket["rows"].append(row)
        bucket["last_at"] = row.get("at") or bucket["last_at"]
        if row.get("session_name"):
            bucket["session_name"] = row["session_name"]
        if row.get("autorun_name"):
            bucket["autorun_name"] = row["autorun_name"]
    sessions = []
    for bucket in grouped.values():
        summary = _summarize(bucket.pop("rows"))
        bucket.update(summary)
        sessions.append(bucket)
    sessions.sort(key=lambda item: item.get("last_at") or "", reverse=True)
    return sessions


def _group_models(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("model_key") or row.get("reported_model") or row.get("model") or "unknown")
        bucket = grouped.setdefault(
            key,
            {
                "model": key,
                "reported_model": row.get("reported_model"),
                "provider": row.get("provider"),
                "rates": row.get("rates"),
                "rows": [],
            },
        )
        bucket["rows"].append(row)
        if row.get("rates"):
            bucket["rates"] = row["rates"]
    models = []
    for bucket in grouped.values():
        summary = _summarize(bucket.pop("rows"))
        bucket.update(summary)
        models.append(bucket)
    models.sort(key=lambda item: item.get("cost_usd") or 0, reverse=True)
    return models


def _int(value: Any) -> int:
    try:
        if value is None or value is False:
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        if value is None or value is False:
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _clip(value: Optional[str], limit: int) -> str:
    text = (value or "").strip().replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
