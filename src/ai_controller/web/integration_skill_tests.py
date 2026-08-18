"""Safe, explicit smoke tests for integration-backed MCP skills."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

import requests

from ...core.config import CTIConfig, SamiConfig
from ...core.config_storage import load_config_from_file, load_raw_config
from ...core.elastic_clusters import client_for_id, skill_vector_for_cluster
from ...core.logging import get_logger
from ...core.skill_vector import (
    CASE_SKILLS,
    SIEM_SKILLS,
    SKILL_GROUPS,
    human_skill_label,
    parse_skill_vector,
)
from ...mcp.mcp_server import SamiGPTMCPServer

logger = get_logger("sami.web.integration_skill_tests")

INTEGRATION_SOLUTIONS = {
    "thehive": "TH",
    "iris": "IRIS",
    "edr": "EDR",
    "cti": "CTI",
    "cti_opencti": "CTI",
    "engineering": "ENG",
}

CRITICAL_SKILLS = {
    "isolate_endpoint",
    "release_endpoint_isolation",
    "kill_process_on_endpoint",
    "collect_forensic_artifacts",
    "close_alert",
    "update_alert_verdict",
    "tag_alert",
    "add_alert_note",
    "execute_rule",
    "execute_runbook",
    "execute_as_agent",
}

NEEDS_REAL_FIXTURE = {
    "get_security_alert_by_id": "Requires a real alert ID; no dummy alert is created.",
    "get_siem_event_by_id": "Requires a real event ID.",
    "get_rule_detections": "Requires a real detection-rule ID.",
    "list_rule_errors": "Requires a real detection-rule ID.",
    "get_endpoint_summary": "Requires a real endpoint ID.",
    "get_detection_details": "Requires a real detection ID.",
    "create_elastic_case": "Creates a persistent Elastic Security case; covered by unit tests instead of the UI probe.",
    "create_fine_tuning_recommendation": "Files an informational Requests note; covered by unit tests.",
    "create_visibility_recommendation": "Files an informational Requests note; covered by unit tests.",
    "add_case_evidence": "Uploads a file that may outlive the case; skipped because cleanup cannot be guaranteed.",
    "assign_case": "Requires a valid platform user; a dummy assignee is not safe.",
}

SIEM_ARGS: Dict[str, Dict[str, Any]] = {
    "search_security_events": {"query": "__sami_skill_test__", "limit": 1},
    "get_file_report": {"file_hash": "0" * 64},
    "get_file_behavior_summary": {"file_hash": "0" * 64},
    "get_entities_related_to_file": {"file_hash": "0" * 64},
    "get_ip_address_report": {"ip": "203.0.113.1"},
    "search_user_activity": {"username": "__sami_skill_test__", "limit": 1},
    "pivot_on_indicator": {"indicator": "203.0.113.1", "limit": 1},
    "search_kql_query": {"kql_query": 'host.name : "__sami_skill_test__"', "limit": 1, "hours_back": 1},
    "get_recent_alerts": {"hours_back": 1, "max_alerts": 1},
    "get_network_events": {"source_ip": "203.0.113.1", "hours_back": 1, "limit": 1},
    "get_dns_events": {"domain": "skill-test.invalid", "hours_back": 1, "limit": 1},
    "get_alerts_by_entity": {"entity_value": "__sami_skill_test__", "entity_type": "host", "hours_back": 1, "limit": 1},
    "get_alerts_by_time_window": {
        "start_time": "2000-01-01T00:00:00Z",
        "end_time": "2000-01-01T00:01:00Z",
        "limit": 1,
    },
    "get_all_uncertain_alerts_for_host": {"hostname": "__sami_skill_test__", "hours_back": 1, "limit": 1},
    "get_email_events": {"sender_email": "skill-test@example.invalid", "hours_back": 1, "limit": 1},
    "get_security_alerts": {"hours_back": 1, "max_alerts": 1},
    "lookup_entity": {"entity_value": "__sami_skill_test__", "entity_type": "host", "hours_back": 1},
    "get_ioc_matches": {"hours_back": 1, "max_matches": 1},
    "get_threat_intel": {"query": "203.0.113.1", "context": {"source": "sami-skill-test"}},
    "list_security_rules": {"limit": 1},
    "search_security_rules": {"query": "__sami_skill_test__"},
    "search_lab_detection_rules": {"query": "powershell", "limit": 3},
    "get_lab_detection_rule": {"rule_name": "PowerShell"},
}


def solution_for_integration(integration_id: str) -> Optional[str]:
    if integration_id.startswith("elastic:"):
        return "SIEM"
    return INTEGRATION_SOLUTIONS.get(integration_id)


def skills_for_integration(integration_id: str) -> List[str]:
    solution = solution_for_integration(integration_id)
    if not solution:
        return []
    for group in SKILL_GROUPS:
        if group["id"] == solution:
            return [str(skill) for skill in group["skills"]]
    return []


def _skip_reason(integration_id: str, skill: str) -> Optional[str]:
    if skill in CRITICAL_SKILLS:
        return "Critical or destructive action; automatic testing is prohibited."
    if skill in NEEDS_REAL_FIXTURE:
        return NEEDS_REAL_FIXTURE[skill]
    if integration_id.startswith("elastic:"):
        cluster_id = integration_id.split(":", 1)[1]
        vector = parse_skill_vector(skill_vector_for_cluster(cluster_id), strict=False)
        if not vector.allows(skill):
            return "Disabled by this Elastic cluster's MCP skill vector."
    return None


def skill_inventory(integration_id: str) -> List[Dict[str, Any]]:
    inventory = []
    for skill in skills_for_integration(integration_id):
        reason = _skip_reason(integration_id, skill)
        inventory.append(
            {
                "id": skill,
                "label": human_skill_label(skill),
                "mode": "skip" if reason else ("create_cleanup" if _uses_temporary_resource(skill) else "read"),
                "skip_reason": reason,
            }
        )
    return inventory


def _uses_temporary_resource(skill: str) -> bool:
    return skill in CASE_SKILLS and skill not in {"list_cases", "search_cases"} or skill in {
        "add_comment_to_fine_tuning_recommendation",
        "add_comment_to_visibility_recommendation",
    }


@dataclass
class ProbeContext:
    integration_id: str
    server: SamiGPTMCPServer
    client: Any = None
    provider: Optional[str] = None


def _build_context(integration_id: str) -> ProbeContext:
    config = load_config_from_file()

    if integration_id == "iris":
        from ...integrations.case_management.iris.iris_client import IRISCaseManagementClient

        client = IRISCaseManagementClient.from_config(config)
        return ProbeContext(integration_id, SamiGPTMCPServer(case_client=client), client)

    if integration_id == "thehive":
        from ...integrations.case_management.thehive.thehive_client import TheHiveCaseManagementClient

        client = TheHiveCaseManagementClient.from_config(config)
        return ProbeContext(integration_id, SamiGPTMCPServer(case_client=client), client)

    if integration_id.startswith("elastic:"):
        cluster_id = integration_id.split(":", 1)[1]
        client = client_for_id(cluster_id)
        if client is None:
            raise ValueError("Elastic cluster client is unavailable")
        server = SamiGPTMCPServer(
            siem_client=client,
            siem_clients={cluster_id: client},
            default_cluster_id=cluster_id,
        )
        return ProbeContext(integration_id, server, client)

    if integration_id in {"cti", "cti_opencti"}:
        raw = load_raw_config()
        section = raw.get(integration_id) if isinstance(raw.get(integration_id), dict) else {}
        cti_type = str(section.get("cti_type") or ("opencti" if integration_id == "cti_opencti" else "local_tip"))
        cti_config = CTIConfig(
            cti_type=cti_type,
            base_url=str(section.get("base_url") or ""),
            api_key=section.get("api_key"),
            timeout_seconds=int(section.get("timeout_seconds") or 30),
            verify_ssl=bool(section.get("verify_ssl", True)),
        )
        scoped = SamiConfig(cti=cti_config)
        if cti_type == "opencti":
            from ...integrations.cti.opencti.opencti_client import OpenCTIClient

            client = OpenCTIClient.from_config(scoped)
        else:
            from ...integrations.cti.local_tip.local_tip_client import LocalTipCTIClient

            client = LocalTipCTIClient.from_config(scoped)
        return ProbeContext(integration_id, SamiGPTMCPServer(cti_client=client), client)

    if integration_id == "engineering":
        provider = str(config.eng.provider if config.eng else "trello").lower()
        if provider == "clickup":
            from ...integrations.eng.clickup.clickup_client import ClickUpClient

            client = ClickUpClient.from_config(config)
        elif provider == "github":
            from ...integrations.eng.github.github_client import GitHubClient

            client = GitHubClient.from_config(config)
        else:
            from ...integrations.eng.trello.trello_client import TrelloClient

            client = TrelloClient.from_config(config)
        return ProbeContext(integration_id, SamiGPTMCPServer(eng_client=client), client, provider)

    if integration_id == "edr":
        # All EDR skills currently require live IDs or perform critical actions.
        return ProbeContext(integration_id, SamiGPTMCPServer())

    raise ValueError("This integration does not expose MCP skills")


async def _execute(server: SamiGPTMCPServer, skill: str, args: Dict[str, Any]) -> Any:
    def run():
        return asyncio.run(server._execute_tool(skill, args))

    result = await asyncio.wait_for(asyncio.to_thread(run), timeout=45)
    if isinstance(result, dict) and result.get("success") is False:
        raise RuntimeError(str(result.get("error") or result.get("message") or "Skill returned success=false"))
    return result


async def _local_tip_existing_hash(context: ProbeContext) -> Optional[str]:
    """Use an existing TIP hash so the POST /hashes upsert cannot create test data."""
    base_url = str(getattr(getattr(context.client, "_http", None), "base_url", "") or "").rstrip("/")
    if not base_url:
        return None

    def fetch() -> Optional[str]:
        response = requests.get(
            f"{base_url}/hashes/recents",
            params={"limit": 1},
            timeout=min(int(getattr(context.client._http, "timeout_seconds", 30)), 15),
            verify=bool(getattr(context.client._http, "verify_ssl", True)),
        )
        response.raise_for_status()
        rows = response.json()
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            value = str(rows[0].get("value") or "").strip()
            return value or None
        return None

    return await asyncio.wait_for(asyncio.to_thread(fetch), timeout=20)


def _safe_message(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    return text[:280] if text else exc.__class__.__name__


async def _create_case_fixture(context: ProbeContext) -> tuple[str, Dict[str, Any]]:
    marker = uuid4().hex[:8]
    result = await _execute(
        context.server,
        "create_case",
        {
            "title": f"[SAMI SKILL TEST {marker}] Temporary case",
            "description": "Temporary automated skill-test case. Safe to delete.",
            "priority": "low",
            "status": "open",
            "tags": ["sami-skill-test", marker],
        },
    )
    case_id = str((result or {}).get("case_id") or ((result or {}).get("case") or {}).get("id") or "")
    if not case_id:
        raise RuntimeError("create_case did not return a case ID")
    return case_id, result


async def _delete_case(context: ProbeContext, case_id: str) -> Dict[str, Any]:
    try:
        await asyncio.wait_for(asyncio.to_thread(context.client.delete_case, case_id), timeout=30)
        return {"attempted": True, "ok": True, "message": f"Temporary case {case_id} deleted."}
    except Exception as exc:
        logger.error("Skill test cleanup failed for case %s: %s", case_id, exc)
        return {
            "attempted": True,
            "ok": False,
            "message": f"Cleanup failed for temporary case {case_id}: {_safe_message(exc)}",
        }


def _case_args(skill: str, case_id: str) -> Dict[str, Any]:
    common: Dict[str, Dict[str, Any]] = {
        "review_case": {"case_id": case_id},
        "add_case_comment": {"case_id": case_id, "content": "SamiGPT automated skill-test comment."},
        "attach_observable_to_case": {
            "case_id": case_id,
            "observable_type": "ip",
            "observable_value": "203.0.113.10",
            "description": "RFC 5737 test address",
            "tags": ["sami-skill-test"],
        },
        "update_case_status": {"case_id": case_id, "status": "in_progress"},
        "get_case_timeline": {"case_id": case_id},
        "add_case_task": {
            "case_id": case_id,
            "title": "SamiGPT skill-test task",
            "description": "Temporary task; parent case will be deleted.",
            "priority": "low",
            "status": "pending",
        },
        "list_case_tasks": {"case_id": case_id},
        "add_case_asset": {
            "case_id": case_id,
            "asset_name": "skill-test-host",
            "asset_type": "host",
            "description": "Temporary test asset",
            "ip_address": "203.0.113.10",
            "hostname": "skill-test.invalid",
            "tags": ["sami-skill-test"],
        },
        "list_case_assets": {"case_id": case_id},
        "list_case_evidence": {"case_id": case_id},
        "update_case": {
            "case_id": case_id,
            "description": "Temporary automated skill-test case (updated).",
            "tags": ["sami-skill-test", "updated"],
        },
        "add_case_timeline_event": {
            "case_id": case_id,
            "title": "SamiGPT skill-test event",
            "content": "Temporary timeline event; parent case will be deleted.",
            "source": "SamiGPT",
            "tags": ["sami-skill-test"],
            "include_in_summary": False,
            "include_in_graph": False,
            "sync_iocs_assets": False,
        },
        "list_case_timeline_events": {"case_id": case_id},
    }
    return common.get(skill, {"case_id": case_id})


async def _test_case_skill(context: ProbeContext, skill: str) -> Dict[str, Any]:
    if skill in {"list_cases", "search_cases"}:
        args = {"limit": 1} if skill == "list_cases" else {"text": "__sami_skill_test__", "limit": 1}
        result = await _execute(context.server, skill, args)
        return {"result": result, "cleanup": None}

    case_ids: List[str] = []
    result: Any = None
    error: Optional[Exception] = None
    try:
        case_id, create_result = await _create_case_fixture(context)
        case_ids.append(case_id)
        if skill == "create_case":
            result = create_result
        elif skill == "link_cases":
            target_id, _ = await _create_case_fixture(context)
            case_ids.append(target_id)
            result = await _execute(
                context.server,
                skill,
                {"source_case_id": case_id, "target_case_id": target_id, "link_type": "related_to"},
            )
        elif skill == "update_case_task_status":
            task_result = await _execute(context.server, "add_case_task", _case_args("add_case_task", case_id))
            task = (task_result or {}).get("task") or {}
            task_id = str(task.get("id") or task.get("task_id") or "")
            if not task_id:
                raise RuntimeError("Temporary task did not return an ID")
            result = await _execute(
                context.server,
                skill,
                {"case_id": case_id, "task_id": task_id, "status": "completed"},
            )
        else:
            result = await _execute(context.server, skill, _case_args(skill, case_id))
    except Exception as exc:
        error = exc
    finally:
        cleanup_results = [await _delete_case(context, case_id) for case_id in reversed(case_ids)]
    return {"result": result, "error": error, "cleanup_records": cleanup_results}


def _extract_eng_id(result: Dict[str, Any]) -> Optional[str]:
    for key in ("card", "task", "project_item"):
        value = result.get(key)
        if isinstance(value, dict) and value.get("id") is not None:
            return str(value["id"])
    return None


async def _delete_eng_item(context: ProbeContext, item_id: str) -> Dict[str, Any]:
    endpoints = {
        "trello": f"/1/cards/{item_id}",
        "clickup": f"/v2/task/{item_id}",
        "github": f"/projects/columns/cards/{item_id}",
    }
    endpoint = endpoints.get(context.provider or "")
    if not endpoint:
        return {"attempted": True, "ok": False, "message": "No cleanup endpoint for engineering provider."}
    try:
        await asyncio.wait_for(asyncio.to_thread(context.client._http.delete, endpoint), timeout=30)
        return {"attempted": True, "ok": True, "message": f"Temporary {context.provider} item deleted."}
    except Exception as exc:
        logger.error("Skill test cleanup failed for %s item %s: %s", context.provider, item_id, exc)
        return {
            "attempted": True,
            "ok": False,
            "message": f"Cleanup failed for temporary {context.provider} item {item_id}: {_safe_message(exc)}",
        }


async def _create_eng_fixture(context: ProbeContext, create_skill: str) -> tuple[str, Dict[str, Any]]:
    marker = uuid4().hex[:8]
    result = await _execute(
        context.server,
        create_skill,
        {
            "title": f"[SAMI SKILL TEST {marker}] Temporary recommendation",
            "description": "Temporary automated skill-test item. Safe to delete.",
            "tags": ["sami-skill-test"],
            "labels": ["sami-skill-test"],
        },
    )
    item_id = _extract_eng_id(result or {})
    if not item_id:
        raise RuntimeError(f"{create_skill} did not return an item ID")
    return item_id, result


async def _test_eng_skill(context: ProbeContext, skill: str) -> Dict[str, Any]:
    if skill.startswith("list_"):
        if context.provider != "clickup":
            return {"skip": f"{skill} is implemented only for ClickUp."}
        return {"result": await _execute(context.server, skill, {})}

    create_skill = (
        "create_fine_tuning_recommendation"
        if "fine_tuning" in skill
        else "create_visibility_recommendation"
    )
    item_id: Optional[str] = None
    result: Any = None
    error: Optional[Exception] = None
    skip: Optional[str] = None
    cleanup_records: List[Dict[str, Any]] = []
    try:
        item_id, create_result = await _create_eng_fixture(context, create_skill)
        if skill.startswith("create_"):
            result = create_result
        elif context.provider != "clickup":
            skip = f"{skill} is implemented only for ClickUp."
        else:
            result = await _execute(
                context.server,
                skill,
                {"task_id": item_id, "comment_text": "SamiGPT automated skill-test comment."},
            )
    except Exception as exc:
        error = exc
    finally:
        if item_id:
            cleanup_records.append(await _delete_eng_item(context, item_id))
    return {
        "result": result,
        "error": error,
        "skip": skip,
        "cleanup_records": cleanup_records,
    }


async def test_skill(context: ProbeContext, skill: str) -> Dict[str, Any]:
    started = time.monotonic()
    record: Dict[str, Any] = {
        "id": skill,
        "label": human_skill_label(skill),
        "status": "failed",
        "message": "",
        "duration_ms": 0,
        "cleanup": None,
    }
    reason = _skip_reason(context.integration_id, skill)
    if reason:
        record.update(status="skipped", message=reason)
        return record

    payload: Dict[str, Any] = {}
    try:
        if skill in CASE_SKILLS:
            payload = await _test_case_skill(context, skill)
        elif skill in SIEM_SKILLS:
            args = SIEM_ARGS.get(skill)
            if args is None:
                record.update(status="skipped", message="No safe dummy input is available for this SIEM skill.")
                return record
            payload = {"result": await _execute(context.server, skill, args)}
        elif skill == "lookup_hash_ti":
            hash_value = "0" * 64
            if context.integration_id == "cti" and context.client.__class__.__name__ == "LocalTipCTIClient":
                hash_value = await _local_tip_existing_hash(context) or ""
                if not hash_value:
                    record.update(
                        status="skipped",
                        message="Local TIP has no existing hash to query safely; creating test indicators is prohibited.",
                    )
                    return record
            payload = {
                "result": await _execute(context.server, skill, {"hash_value": hash_value}),
                "success_message": (
                    "Existing Local TIP hash lookup completed; no test indicator was created."
                    if context.integration_id == "cti"
                    else "Dummy threat-intel lookup completed."
                ),
            }
        elif solution_for_integration(context.integration_id) == "ENG":
            payload = await _test_eng_skill(context, skill)
            if payload.get("skip"):
                record.update(status="skipped", message=payload["skip"])
            else:
                record.update(status="passed", message="Dummy skill call completed.")
        else:
            record.update(status="skipped", message="No safe automated test is defined.")

        if payload.get("error"):
            raise payload["error"]
        if record["status"] == "failed":
            record.update(
                status="passed",
                message=payload.get("success_message") or "Dummy skill call completed.",
            )
    except Exception as exc:
        record.update(status="failed", message=_safe_message(exc))
    finally:
        cleanup_records: List[Dict[str, Any]] = payload.get("cleanup_records") or []
        if cleanup_records:
            cleanup_ok = all(item.get("ok") for item in cleanup_records)
            record["cleanup"] = {
                "attempted": True,
                "ok": cleanup_ok,
                "message": " ".join(str(item.get("message") or "") for item in cleanup_records),
            }
            if not cleanup_ok:
                record["status"] = "failed"
                record["message"] = "Skill ran, but automatic cleanup failed. Review the cleanup message."
        record["duration_ms"] = int((time.monotonic() - started) * 1000)
    return record


async def run_skill_tests(integration_id: str, selected: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    available = skills_for_integration(integration_id)
    requested = list(dict.fromkeys(selected or available))
    unknown = [skill for skill in requested if skill not in available]
    if unknown:
        raise ValueError(f"Skills do not belong to this integration: {', '.join(unknown)}")
    context = _build_context(integration_id)
    results = []
    for skill in requested:
        logger.info("Integration skill test started integration=%s skill=%s", integration_id, skill)
        record = await test_skill(context, skill)
        results.append(record)
        logger.info(
            "Integration skill test finished integration=%s skill=%s status=%s cleanup_ok=%s",
            integration_id,
            skill,
            record["status"],
            (record.get("cleanup") or {}).get("ok"),
        )
    counts = {
        status: sum(1 for item in results if item["status"] == status)
        for status in ("passed", "failed", "skipped")
    }
    return {
        "success": counts["failed"] == 0,
        "integration_id": integration_id,
        "counts": counts,
        "skills": results,
    }
