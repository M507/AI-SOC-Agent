"""Push a local Detection as Code rule file to Kibana after Implement.

Mirrors Home-Lab-Rules ``deploy_local_rule`` / ``sync_rules``: upsert the
exception list and items, merge content onto the live detection-engine
rule, PUT it, then refresh ``_dac`` sync hashes on disk. The local folder
remains the source of truth; this is the Elastic deploy step.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.errors import IntegrationError
from ...core.logging import get_logger
from .errors import DetectionError
from .rules_store import _write_json

logger = get_logger("sami.detection.elastic_sync")

RULES_PATH = "/api/detection_engine/rules"
EXCEPTION_LISTS_PATH = "/api/exception_lists"
EXCEPTION_ITEMS_PATH = "/api/exception_lists/items"
EXCEPTION_ITEMS_FIND_PATH = "/api/exception_lists/items/_find"

READ_ONLY_RULE_FIELDS = frozenset(
    {
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
        "execution_summary",
        "immutable",
        "rule_source",
    }
)

CONTENT_FIELDS = frozenset(
    {
        "query",
        "description",
        "note",
        "setup",
        "severity",
        "risk_score",
        "tags",
        "threat",
        "references",
        "false_positives",
        "filters",
        "index",
        "from",
        "to",
        "interval",
        "max_signals",
        "version",
        "exceptions_list",
        "risk_score_mapping",
        "severity_mapping",
        "investigation_fields",
        "alert_suppression",
        "timestamp_override",
        "timestamp_override_fallback_disabled",
        "building_block_type",
        "license",
        "related_integrations",
        "required_fields",
        "threat_index",
        "threat_query",
        "threat_mapping",
        "threat_filters",
        "threat_indicator_path",
        "rule_name_override",
        "timeline_id",
        "timeline_title",
        "data_view_id",
        "runtime_mappings",
        "event_category_override",
        "tiebreaker_field",
        "timestamp_field",
        "response_actions",
        "actions",
        "type",
        "language",
        "new_terms_fields",
        "history_window_start",
        "threshold",
        "threshold_field",
        "threshold_value",
        "anomaly_threshold",
        "machine_learning_job_id",
        "enabled",
    }
)

READ_ONLY_ITEM_FIELDS = frozenset(
    {
        "id",
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
        "_version",
        "tie_breaker_id",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_hash(rule: Dict[str, Any], exception_items: Optional[List[Dict[str, Any]]] = None) -> str:
    payload: Any = {"rule": rule, "exception_items": exception_items or []}
    if not exception_items:
        payload = rule
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _kibana(client: Any):
    if client is None:
        raise DetectionError("No Elastic cluster is configured to sync the rule.", status_code=409)
    try:
        return client._cases_http()
    except Exception as exc:  # noqa: BLE001
        raise DetectionError(f"Could not reach Kibana: {exc}", status_code=502) from exc


def _kbn_get(http: Any, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    return http.get(path, params=params)


def _kbn_put(http: Any, path: str, body: Dict[str, Any]) -> Any:
    return http.put(path, json_data=body)


def _kbn_post(http: Any, path: str, body: Dict[str, Any]) -> Any:
    return http.post(path, json_data=body)


def _strip_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in item.items() if key not in READ_ONLY_ITEM_FIELDS}


def _prepare_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    payload = {key: value for key, value in rule.items() if key not in READ_ONLY_RULE_FIELDS}
    if "rule_id" in payload and "id" in payload:
        del payload["id"]
    return payload


def _merge_rule(local_rule: Dict[str, Any], remote_rule: Dict[str, Any], *, enabled: bool) -> Dict[str, Any]:
    payload = deepcopy(remote_rule)
    for field in CONTENT_FIELDS:
        if field in local_rule:
            payload[field] = local_rule[field]
    payload["enabled"] = enabled
    if remote_rule.get("immutable") and "author" in remote_rule:
        payload["author"] = remote_rule["author"]
    return _prepare_rule(payload)


def _ensure_exception_list(http: Any, *, list_id: str, rule_name: str, namespace_type: str) -> Dict[str, Any]:
    try:
        return _kbn_get(http, EXCEPTION_LISTS_PATH, params={"list_id": list_id})
    except IntegrationError as exc:
        if "404" not in str(exc):
            raise
    return _kbn_post(
        http,
        EXCEPTION_LISTS_PATH,
        {
            "list_id": list_id,
            "name": f"{rule_name} - DaC exceptions",
            "description": "Rule exceptions managed via SamiGPT Detection as Code",
            "namespace_type": namespace_type,
            "type": "detection",
        },
    )


def _upsert_exception_item(http: Any, item: Dict[str, Any]) -> Dict[str, Any]:
    payload = _strip_item(item)
    list_id = payload.get("list_id")
    item_id = payload.get("item_id")
    if not list_id or not item_id:
        raise DetectionError("Exception item requires list_id and item_id.")
    try:
        existing = _kbn_get(http, EXCEPTION_ITEMS_PATH, params={"list_id": list_id, "item_id": item_id})
        update = deepcopy(payload)
        update["id"] = existing["id"]
        if "_version" in existing:
            update["_version"] = existing["_version"]
        return _kbn_put(http, EXCEPTION_ITEMS_PATH, update)
    except IntegrationError as exc:
        if "404" not in str(exc):
            raise
        return _kbn_post(http, EXCEPTION_ITEMS_PATH, payload)


def _canonical_exception_list_id(
    rule_id: str,
    exceptions_list: List[Dict[str, Any]],
    exception_items: List[Dict[str, Any]],
) -> str:
    """Prefer an existing dac-* list on the rule, else the Home-Lab-Rules default."""
    from .apply import default_exception_list_id

    preferred = default_exception_list_id(rule_id)
    for ref in exceptions_list or []:
        list_id = str((ref or {}).get("list_id") or "")
        if list_id.startswith("dac-") and list_id.endswith("-exceptions"):
            return list_id
    for item in exception_items or []:
        list_id = str((item or {}).get("list_id") or "")
        if list_id.startswith("dac-") and list_id.endswith("-exceptions"):
            return list_id
    # Legacy sami-* items still map onto the shared dac list.
    return preferred


def _sync_exceptions(
    http: Any,
    *,
    rule_id: str,
    rule_name: str,
    exceptions_list: List[Dict[str, Any]],
    exception_items: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not exception_items:
        # Drop incomplete refs (no Kibana id) so a later PUT does not 400.
        return [
            ref for ref in (exceptions_list or [])
            if isinstance(ref, dict) and ref.get("id") and ref.get("list_id")
        ], exception_items

    list_id = _canonical_exception_list_id(rule_id, exceptions_list, exception_items)
    namespace_type = str(exception_items[0].get("namespace_type") or "single")
    exc_list = _ensure_exception_list(
        http, list_id=list_id, rule_name=rule_name or rule_id, namespace_type=namespace_type
    )

    synced_items: List[Dict[str, Any]] = []
    for item in exception_items:
        payload = deepcopy(item)
        payload["list_id"] = list_id
        payload.setdefault("namespace_type", namespace_type)
        payload.setdefault("type", "simple")
        synced_items.append(_strip_item(_upsert_exception_item(http, payload)))

    synced_ref = {
        "id": exc_list["id"],
        "list_id": list_id,
        "type": exc_list.get("type", "detection"),
        "namespace_type": exc_list.get("namespace_type", namespace_type),
    }
    # Keep other complete remote/local refs; never keep id-less stubs (Kibana 400).
    # Collapse legacy sami-* / duplicate dac refs into the canonical synced_ref.
    updated_refs: List[Dict[str, Any]] = []
    seen_lists = {list_id}
    updated_refs.append(synced_ref)
    for ref in exceptions_list or []:
        if not isinstance(ref, dict):
            continue
        other_id = str(ref.get("list_id") or "")
        if not other_id or other_id in seen_lists:
            continue
        if other_id.startswith("sami-") and other_id.endswith("-exceptions"):
            continue
        if not ref.get("id"):
            continue
        updated_refs.append({
            "id": ref["id"],
            "list_id": other_id,
            "type": ref.get("type") or "detection",
            "namespace_type": ref.get("namespace_type") or namespace_type,
        })
        seen_lists.add(other_id)
    return updated_refs, synced_items


def _get_remote_rule(http: Any, *, rule_id: str, elastic_id: str = "") -> Dict[str, Any]:
    params: Dict[str, str] = {}
    if rule_id:
        params["rule_id"] = rule_id
    elif elastic_id:
        params["id"] = elastic_id
    else:
        raise DetectionError("Rule id is required to sync to Elastic.")
    return _kbn_get(http, RULES_PATH, params=params)


def push_rule_file(client: Any, path: Path) -> Dict[str, Any]:
    """Sync one local rule JSON file to Kibana and refresh ``_dac`` sync metadata."""
    path = Path(path)
    if not path.is_file():
        raise DetectionError(f"Rule file is missing: {path}", status_code=404)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DetectionError(f"Could not read rule file for sync: {exc}", status_code=422) from exc
    if not isinstance(data, dict):
        raise DetectionError("Rule file is not a JSON object.", status_code=422)

    dac = dict(data.get("_dac") or {})
    rule = dict(data.get("rule") or {})
    items = list(data.get("exception_items") or [])
    rule_id = str(dac.get("rule_id") or rule.get("rule_id") or "")
    elastic_id = str(dac.get("elastic_id") or rule.get("id") or "")
    rule_name = str(rule.get("name") or dac.get("name") or rule_id)
    status = str(dac.get("status") or ("enabled" if rule.get("enabled", True) else "disabled"))
    enabled = status != "disabled"
    rule["enabled"] = enabled

    http = _kibana(client)
    created = False
    try:
        exceptions_list, synced_items = _sync_exceptions(
            http,
            rule_id=rule_id,
            rule_name=rule_name,
            exceptions_list=list(rule.get("exceptions_list") or []),
            exception_items=items,
        )
        rule["exceptions_list"] = exceptions_list
        try:
            remote = _get_remote_rule(http, rule_id=rule_id, elastic_id=elastic_id)
        except IntegrationError as lookup_exc:
            # Net-new Visibility rules are not in Kibana yet — create via POST.
            if "404" not in str(lookup_exc):
                raise
            create_payload = _prepare_rule({**rule, "enabled": enabled})
            if "rule_id" not in create_payload and rule_id:
                create_payload["rule_id"] = rule_id
            updated = _kbn_post(http, RULES_PATH, create_payload)
            created = True
        else:
            payload = _merge_rule(rule, remote, enabled=enabled)
            updated = _kbn_put(http, RULES_PATH, payload)
    except IntegrationError as exc:
        logger.exception("Elastic rule sync failed for %s", rule_id or path.name)
        message = str(exc)
        if "lists-all" in message or ("exception_lists" in message and "403" in message):
            message = (
                f"{exc}. The Elasticsearch API key cannot write exception lists. "
                "Set elastic.clusters[].kibana_api_key (and kibana_url) to a Kibana "
                "API key with lists-all / detection privileges, then Implement again."
            )
        raise DetectionError(f"Elastic sync failed: {message}", status_code=502) from exc
    except DetectionError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Elastic rule sync failed for %s", rule_id or path.name)
        raise DetectionError(f"Elastic sync failed: {exc}", status_code=502) from exc

    if not enabled:
        updated["enabled"] = False

    data["rule"] = updated
    data["exception_items"] = synced_items if synced_items else items
    digest = content_hash(updated, data["exception_items"])
    dac.update(
        {
            "status": "disabled" if not enabled else "enabled",
            "elastic_id": updated.get("id") or dac.get("elastic_id") or "",
            "rule_id": updated.get("rule_id") or rule_id,
            "name": updated.get("name") or rule_name,
            "revision": updated.get("revision"),
            "content_hash": digest,
            "last_synced_hash": digest,
            "last_synced_at": _utc_now(),
        }
    )
    data["_dac"] = dac
    file_sha = _write_json(path, data)
    logger.info(
        "Synced rule %s to Elastic (revision %s)",
        dac.get("name") or rule_id,
        updated.get("revision"),
    )
    return {
        "synced": True,
        "created": created,
        "rule_id": dac.get("rule_id") or rule_id,
        "rule_name": dac.get("name") or rule_name,
        "revision": updated.get("revision"),
        "enabled": enabled,
        "exception_count": len(data.get("exception_items") or []),
        "file": str(path),
        "file_sha256": file_sha,
    }


def push_rule_after_implement(client: Any, *, file_path: str) -> Dict[str, Any]:
    """Entry point used by Implement. ``client`` is the SIEM client for the cluster."""
    return push_rule_file(client, Path(file_path))
