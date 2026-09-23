"""Local Home Lab detection-rule catalog (token-efficient search + lookup).

Rules live on disk under Home-Lab-Rules. The model never sees all 1k+ full
documents: search returns compact hits, and get_rule loads one excerpt.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.logging import get_logger

logger = get_logger("sami.lab_rules")

DEFAULT_RULES_DIR = Path("/root/Home-Lab-Rules/rules/elastic_1/rules")
_UUID_RE = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.I,
)
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{2,}", re.I)
_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "have", "has", "had",
    "not", "but", "are", "was", "were", "been", "being", "into", "over", "under",
    "via", "using", "used", "use", "gap", "visibility", "missing", "need",
    "needs", "improve", "improvement", "logging", "telemetry", "coverage",
    "detection", "rule", "rules", "alert", "alerts", "fine", "tune", "tuning",
    "recommendation", "suggest", "suggestion", "please", "should", "would",
    "could", "there", "their", "about", "when", "where", "what", "which",
}

_INDEX_CACHE: Dict[str, Any] = {"mtime": None, "path": None, "records": []}


def rules_dir() -> Path:
    override = os.environ.get("SAMI_LAB_RULES_DIR", "").strip()
    return Path(override) if override else DEFAULT_RULES_DIR


def clear_index_cache() -> None:
    _INDEX_CACHE["mtime"] = None
    _INDEX_CACHE["path"] = None
    _INDEX_CACHE["records"] = []


def _tokenize(text: str) -> List[str]:
    tokens = []
    for match in _TOKEN_RE.finditer((text or "").lower()):
        token = match.group(0)
        if token in _STOPWORDS or token.isdigit():
            continue
        tokens.append(token)
    return tokens


def _compact_query(query: Any, limit: int = 400) -> str:
    text = query if isinstance(query, str) else json.dumps(query or "", ensure_ascii=False)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _record_from_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("Skip unreadable rule %s: %s", path, exc)
        return None
    dac = data.get("_dac") if isinstance(data.get("_dac"), dict) else {}
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    tags = [str(item) for item in (rule.get("tags") or []) if item]
    data_sources = [
        tag.split(":", 1)[-1].strip()
        for tag in tags
        if tag.lower().startswith("data source:")
    ]
    indexes = rule.get("index") or []
    if isinstance(indexes, str):
        indexes = [indexes]
    rule_id = str(dac.get("rule_id") or rule.get("rule_id") or "")
    file_uuid = ""
    match = _UUID_RE.search(path.name)
    if match:
        file_uuid = match.group(1)
    if not rule_id:
        rule_id = file_uuid
    name = str(rule.get("name") or dac.get("name") or path.stem)
    enabled = bool(rule.get("enabled") if "enabled" in rule else str(path.name).startswith("[enabled]"))
    description = str(rule.get("description") or "")
    query = rule.get("query") or ""
    return {
        "rule_id": rule_id,
        "elastic_id": str(dac.get("elastic_id") or rule.get("id") or ""),
        "name": name,
        "enabled": enabled,
        "language": str(rule.get("language") or rule.get("type") or ""),
        "tags": tags[:12],
        "data_sources": data_sources[:8],
        "index": [str(item) for item in indexes[:8]],
        "description": " ".join(description.split())[:240],
        "query_excerpt": _compact_query(query, 360),
        "file": str(path),
        "path": path,
        "_search": " ".join(
            [
                name,
                rule_id,
                file_uuid,
                " ".join(tags),
                " ".join(data_sources),
                " ".join(str(item) for item in indexes),
                description[:400],
                _compact_query(query, 500),
            ]
        ).lower(),
    }


def _load_index(force: bool = False) -> List[Dict[str, Any]]:
    directory = rules_dir()
    try:
        mtime = directory.stat().st_mtime if directory.is_dir() else None
    except OSError:
        mtime = None
    cached_path = _INDEX_CACHE.get("path")
    if (
        not force
        and cached_path == str(directory)
        and _INDEX_CACHE.get("mtime") == mtime
        and _INDEX_CACHE.get("records")
    ):
        return _INDEX_CACHE["records"]
    records: List[Dict[str, Any]] = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            record = _record_from_file(path)
            if record:
                records.append(record)
    _INDEX_CACHE["path"] = str(directory)
    _INDEX_CACHE["mtime"] = mtime
    _INDEX_CACHE["records"] = records
    logger.info("Loaded %s Home Lab detection rules from %s", len(records), directory)
    return records


def search_rules(query: str, limit: int = 8) -> List[Dict[str, Any]]:
    """Keyword search over the compact index. Default 8 hits to keep tokens low."""
    limit = max(1, min(int(limit or 8), 15))
    tokens = _tokenize(query)
    records = _load_index()
    if not tokens:
        return [_public_hit(record, 0) for record in records[:limit]]
    scored: List[Tuple[int, Dict[str, Any]]] = []
    for record in records:
        haystack = record["_search"]
        score = 0
        name = record["name"].lower()
        for token in tokens:
            if token == (record.get("rule_id") or "").lower() or token == (record.get("elastic_id") or "").lower():
                score += 50
            elif token in name:
                score += 6
            elif token in haystack:
                score += 2
        if score:
            scored.append((score, record))
    scored.sort(key=lambda item: (-item[0], item[1]["name"]))
    return [_public_hit(record, score) for score, record in scored[:limit]]


def get_rule(rule_id: Optional[str] = None, rule_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load one rule excerpt (query included; investigation notes omitted)."""
    needle_id = (rule_id or "").strip().lower()
    needle_name = (rule_name or "").strip().lower()
    if not needle_id and not needle_name:
        return None
    for record in _load_index():
        ids = {
            (record.get("rule_id") or "").lower(),
            (record.get("elastic_id") or "").lower(),
        }
        name = (record.get("name") or "").lower()
        if needle_id and needle_id in ids:
            return _rule_excerpt(record)
        if needle_name and (needle_name == name or needle_name in name):
            return _rule_excerpt(record)
    if needle_id:
        match = _UUID_RE.search(needle_id)
        if match:
            uuid = match.group(1).lower()
            for record in _load_index():
                if uuid in (record.get("rule_id") or "").lower() or uuid in (record.get("file") or "").lower():
                    return _rule_excerpt(record)
    return None


def _public_hit(record: Dict[str, Any], score: int = 0) -> Dict[str, Any]:
    return {
        "rule_id": record.get("rule_id"),
        "name": record.get("name"),
        "enabled": record.get("enabled"),
        "language": record.get("language"),
        "tags": record.get("tags") or [],
        "data_sources": record.get("data_sources") or [],
        "index": record.get("index") or [],
        "query_excerpt": record.get("query_excerpt") or "",
        "score": score,
    }


def _rule_excerpt(record: Dict[str, Any]) -> Dict[str, Any]:
    path = record.get("path")
    query = ""
    false_positives: List[Any] = []
    exceptions: List[Any] = []
    description = record.get("description") or ""
    if isinstance(path, Path) and path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
            query = rule.get("query") or ""
            if isinstance(query, str) and len(query) > 4000:
                query = query[:3999] + "…"
            false_positives = rule.get("false_positives") or []
            exceptions = rule.get("exceptions_list") or []
            description = str(rule.get("description") or description)
        except Exception:
            pass
    return {
        "found": True,
        "rule_id": record.get("rule_id"),
        "elastic_id": record.get("elastic_id"),
        "name": record.get("name"),
        "enabled": record.get("enabled"),
        "language": record.get("language"),
        "index": record.get("index") or [],
        "tags": record.get("tags") or [],
        "data_sources": record.get("data_sources") or [],
        "description": " ".join(str(description).split())[:800],
        "query": query,
        "false_positives": false_positives[:8] if isinstance(false_positives, list) else false_positives,
        "exceptions_list": exceptions if isinstance(exceptions, list) else [],
        "file": record.get("file"),
    }


def enrich_fine_tune(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the Home Lab rule and keep the AI text as a suggestion only."""
    enriched = dict(payload or {})
    suggestion = str(enriched.get("description") or enriched.get("suggestion") or "").strip()
    if suggestion:
        enriched["suggestion"] = suggestion
    rule = get_rule(
        rule_id=enriched.get("rule_id") or enriched.get("elastic_id"),
        rule_name=enriched.get("rule_name") or enriched.get("name") or enriched.get("title"),
    )
    if rule is None and suggestion:
        hits = search_rules(
            " ".join(
                str(enriched.get(key) or "")
                for key in ("rule_name", "title", "suggestion", "description")
            ),
            limit=1,
        )
        if hits and hits[0].get("score", 0) >= 6:
            rule = get_rule(rule_id=hits[0].get("rule_id"), rule_name=hits[0].get("name"))
    enriched["rule_found"] = bool(rule)
    enriched["rule"] = rule or {
        "found": False,
        "message": "No matching rule in /root/Home-Lab-Rules/rules/elastic_1/rules/",
    }
    return enriched


def enrich_visibility(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Re-check the local rule catalog before treating something as a gap."""
    enriched = dict(payload or {})
    suggestion = str(enriched.get("description") or enriched.get("suggestion") or "").strip()
    if suggestion:
        enriched["suggestion"] = suggestion
    query = " ".join(
        str(enriched.get(key) or "")
        for key in ("source", "title", "suggestion", "description")
    )
    hits = search_rules(query, limit=6)
    likely_covered = bool(hits and hits[0].get("score", 0) >= 8)
    enriched["coverage_check"] = {
        "likely_gap": not likely_covered,
        "likely_covered": likely_covered,
        "query_used": " ".join(_tokenize(query)[:24]),
        "matching_rules": hits,
        "strategy": (
            "Compact Home Lab rule index (name, tags, data sources, indexes, query excerpt). "
            "Search with specific keywords; load at most one or two full rules. "
            "Do not dump the catalog into the model."
        ),
    }
    return enriched
