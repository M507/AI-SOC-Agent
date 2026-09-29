"""Read and write rule JSON in the configured folder.

The folder path is the only external input. Files are never copied into
this repository. suggested_fields.json lives beside the rules and is not
a rule: the indexer skips that name, and Findings unions its names with
each rule's investigation_fields. Writes go through a temp file in the
same directory so a crash does not truncate the rule. The sha256 captured
at draft time is checked again at Implement so a file edited outside the
review is not overwritten. See documentation/detection-as-code.md.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..approval_queue.lab_rules import clear_index_cache, get_rule, rules_dir, search_rules
from .errors import DetectionError
from .settings import public_settings


SUGGESTED_FIELDS_FILE = "suggested_fields.json"
_SUGGESTED_CACHE: Dict[str, Any] = {"path": None, "mtime": None, "fields": frozenset()}


def field_name_set(value: Any) -> set:
    """Accept a name list, one name, or Elastic's ``{field_names: [...]}`` object."""
    if isinstance(value, dict):
        value = value.get("field_names") or value.get("fields") or []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return set()
    return {str(item).strip() for item in value if str(item).strip()}


def load_suggested_fields() -> set:
    """Extra suggestion names from suggested_fields.json in the rules folder."""
    path = rules_dir() / SUGGESTED_FIELDS_FILE
    try:
        mtime = path.stat().st_mtime if path.is_file() else None
    except OSError:
        mtime = None
    if _SUGGESTED_CACHE.get("path") == str(path) and _SUGGESTED_CACHE.get("mtime") == mtime:
        return set(_SUGGESTED_CACHE["fields"])
    fields: set = set()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fields = field_name_set(data if isinstance(data, list) else (data or {}).get("fields"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            from ...core.logging import get_logger

            get_logger("sami.detection.rules").warning("Could not read %s: %s", path, exc)
    _SUGGESTED_CACHE["path"] = str(path)
    _SUGGESTED_CACHE["mtime"] = mtime
    _SUGGESTED_CACHE["fields"] = frozenset(fields)
    return fields


def highlighted_field_names(data: Dict[str, Any]) -> set:
    """Custom highlighted fields stored on the rule as investigation_fields."""
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    return field_name_set(rule.get("investigation_fields"))


def folder_status() -> Dict[str, Any]:
    path = rules_dir()
    settings = public_settings(path)
    settings["configured"] = path.is_dir()
    settings["path"] = str(path)
    return settings


def require_folder() -> Path:
    status = folder_status()
    if not status["configured"]:
        raise DetectionError(
            "Rules folder is not configured. Set it under Settings, General, Detection as Code.",
            status_code=409,
        )
    return Path(status["path"])


def search_catalog(query: str = "", limit: int = 50) -> Dict[str, Any]:
    status = folder_status()
    if not status["configured"]:
        return {"configured": False, "path": status["path"], "rules": []}
    rules = search_rules(query or "", limit=limit)
    return {"configured": True, "path": status["path"], "rules": rules}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_rule_file(rule_id: Optional[str] = None, rule_name: Optional[str] = None) -> Tuple[Path, Dict[str, Any], str]:
    """Return the on-disk document, its path, and the sha256 of the file bytes."""
    require_folder()
    excerpt = get_rule(rule_id=rule_id, rule_name=rule_name)
    if not excerpt or not excerpt.get("file"):
        raise DetectionError("No matching rule file in the configured folder.", status_code=404)
    path = Path(str(excerpt["file"]))
    if not path.is_file():
        raise DetectionError("The rule file is no longer on disk.", status_code=404)
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DetectionError(f"Could not read the rule file: {exc}", status_code=422) from exc
    if not isinstance(data, dict):
        raise DetectionError("Rule file is not a JSON object.", status_code=422)
    return path, data, _sha256(raw)


def rule_detail(rule_id: str) -> Dict[str, Any]:
    path, data, digest = load_rule_file(rule_id=rule_id)
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    dac = data.get("_dac") if isinstance(data.get("_dac"), dict) else {}
    items = data.get("exception_items") if isinstance(data.get("exception_items"), list) else []
    query = rule.get("query") or ""
    if isinstance(query, str) and len(query) > 8000:
        query = query[:7999] + "…"
    return {
        "found": True,
        "rule_id": dac.get("rule_id") or rule.get("rule_id") or rule_id,
        "name": rule.get("name") or dac.get("name") or path.stem,
        "enabled": bool(rule.get("enabled", str(path.name).startswith("[enabled]"))),
        "severity": rule.get("severity") or "",
        "language": rule.get("language") or "",
        "description": str(rule.get("description") or "")[:2000],
        "query": query,
        "tags": rule.get("tags") or [],
        "exception_items": items,
        "exception_count": len(items),
        "file": str(path),
        "file_sha256": digest,
        "status": dac.get("status") or ("enabled" if str(path.name).startswith("[enabled]") else "disabled"),
    }


def _write_json(path: Path, data: Dict[str, Any]) -> str:
    # Same-directory temp file, then replace. A crash mid-write leaves the original.
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
    clear_index_cache()
    return _sha256(path.read_bytes())


def render_with_exceptions(data: Dict[str, Any], additions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a copy of the document with the given exception items appended."""
    updated = json.loads(json.dumps(data))
    items = list(updated.get("exception_items") or [])
    items.extend(additions)
    updated["exception_items"] = items
    return updated


def render_disabled(data: Dict[str, Any]) -> Dict[str, Any]:
    updated = json.loads(json.dumps(data))
    dac = dict(updated.get("_dac") or {})
    dac["status"] = "disabled"
    updated["_dac"] = dac
    rule = dict(updated.get("rule") or {})
    rule["enabled"] = False
    updated["rule"] = rule
    return updated


def apply_additions(path: Path, data: Dict[str, Any], additions: List[Dict[str, Any]], expected_sha256: str) -> Dict[str, Any]:
    current = _sha256(path.read_bytes())
    if expected_sha256 and current != expected_sha256:
        raise DetectionError(
            "The rule file changed after this draft. Reload the review and draft again.",
            status_code=409,
        )
    updated = render_with_exceptions(data, additions)
    digest = _write_json(path, updated)
    return {"file": str(path), "file_sha256": digest, "added": len(additions)}


def apply_disable(path: Path, data: Dict[str, Any], expected_sha256: str) -> Dict[str, Any]:
    current = _sha256(path.read_bytes())
    if expected_sha256 and current != expected_sha256:
        raise DetectionError(
            "The rule file changed after this draft. Reload the review and draft again.",
            status_code=409,
        )
    updated = render_disabled(data)
    name = path.name
    rest = name
    for prefix in ("[enabled]_", "[disabled]_"):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            break
    target = path.with_name(f"[disabled]_{rest}")
    if target == path:
        digest = _write_json(path, updated)
        return {"file": str(path), "file_sha256": digest, "status": "disabled"}
    # Write the disabled copy first. The enabled file stays intact if this fails.
    if target.exists():
        raise DetectionError(f"A disabled rule file already exists at {target.name}.", status_code=409)
    digest = _write_json(target, updated)
    path.unlink()
    clear_index_cache()
    return {"file": str(target), "file_sha256": digest, "status": "disabled"}


def document_text(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
