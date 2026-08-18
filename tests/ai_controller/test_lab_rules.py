import json

import pytest

from src.ai_controller.approval_queue.lab_rules import (
    clear_index_cache,
    enrich_fine_tune,
    enrich_visibility,
    get_rule,
    search_rules,
)
from src.ai_controller.approval_queue.models import RequestStatus
from src.ai_controller.approval_queue.service import ApprovalQueue


def _write_rule(directory, *, enabled=True, name="Suspicious PowerShell Encoded Command", rule_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"):
    prefix = "[enabled]" if enabled else "[disabled]"
    path = directory / f"{prefix}_{name.replace(' ', '_')}_{rule_id}.json"
    path.write_text(
        json.dumps(
            {
                "_dac": {
                    "rule_id": rule_id,
                    "elastic_id": "elastic-" + rule_id[:8],
                    "name": name,
                },
                "rule": {
                    "name": name,
                    "description": "Detects encoded PowerShell command lines on endpoints.",
                    "query": "process.name: powershell.exe and process.args: *-enc*",
                    "language": "kuery",
                    "index": ["logs-endpoint.events.process-*"],
                    "tags": ["Data Source: Elastic Endgame", "Domain: Endpoint"],
                    "false_positives": ["admin scripts"],
                    "exceptions_list": [],
                    "enabled": enabled,
                    "note": "Long investigation notes that must not be sent to the model.",
                },
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def lab_rules_dir(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    _write_rule(rules)
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(rules))
    clear_index_cache()
    yield rules
    clear_index_cache()


def test_search_returns_compact_hits(lab_rules_dir):
    hits = search_rules("encoded powershell", limit=8)
    assert hits
    assert hits[0]["name"] == "Suspicious PowerShell Encoded Command"
    assert "powershell.exe" in hits[0]["query_excerpt"]
    assert "note" not in hits[0]
    assert len(hits) <= 8


def test_get_rule_omits_investigation_note(lab_rules_dir):
    rule = get_rule(rule_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert rule["found"] is True
    assert "powershell.exe" in rule["query"]
    assert "investigation notes" not in (rule.get("note") or "")
    assert "note" not in rule


def test_fine_tune_create_is_informational(lab_rules_dir, tmp_path):
    queue = ApprovalQueue(str(tmp_path / "queue"))
    created = queue.create(
        "fine_tune",
        "Tune encoded PowerShell",
        "Too many lab admin FPs.",
        payload={
            "title": "Tune encoded PowerShell",
            "description": "Exclude signed build-server user when command matches the internal helper.",
            "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        },
    )
    assert created.status is RequestStatus.INFORMATIONAL
    assert created.payload["rule_found"] is True
    assert created.payload["rule"]["query"]
    assert "internal helper" in created.payload["suggestion"]
    with pytest.raises(ValueError, match="Informational"):
        queue.approve(created.id)
    with pytest.raises(ValueError, match="Informational"):
        queue.deny(created.id)


def test_visibility_coverage_check_flags_existing_rule(lab_rules_dir):
    covered = enrich_visibility(
        {
            "title": "Need encoded PowerShell detection",
            "description": "We are missing encoded powershell.exe command-line coverage.",
            "source": "endpoint",
        }
    )
    assert covered["coverage_check"]["likely_covered"] is True
    assert covered["coverage_check"]["likely_gap"] is False
    assert covered["coverage_check"]["matching_rules"]

    gap = enrich_visibility(
        {
            "title": "Okta MFA fatigue",
            "description": "Repeated Okta push notification deny-then-accept is not detected.",
            "source": "Okta",
        }
    )
    assert gap["coverage_check"]["likely_gap"] is True


def test_visibility_create_stores_coverage(lab_rules_dir, tmp_path):
    queue = ApprovalQueue(str(tmp_path / "queue"))
    created = queue.create(
        "visibility",
        "Okta MFA fatigue",
        "No Home Lab rule for push fatigue.",
        payload={
            "title": "Okta MFA fatigue",
            "description": "Repeated Okta push notification deny-then-accept is not detected.",
            "source": "Okta",
        },
    )
    assert created.status is RequestStatus.INFORMATIONAL
    assert "coverage_check" in created.payload
    assert created.payload["coverage_check"]["likely_gap"] is True
    listed = queue.list(status="pending")
    assert any(item.id == created.id for item in listed)


def test_enrich_fine_tune_finds_rule_by_name(lab_rules_dir):
    payload = enrich_fine_tune(
        {
            "title": "Suspicious PowerShell Encoded Command",
            "description": "Add an exception for the helpdesk jump box.",
            "rule_name": "Suspicious PowerShell Encoded Command",
        }
    )
    assert payload["rule_found"] is True
    assert payload["rule"]["rule_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_mcp_fine_tune_and_search_without_eng(lab_rules_dir, tmp_path, monkeypatch):
    import asyncio
    import json

    from src.ai_controller.approval_queue import service as queue_service
    from src.mcp.mcp_server import SamiGPTMCPServer

    queue_service.init_queue(str(tmp_path / "queue"))
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:N/TH:N/SIEM:Y/EDR:N/CTI:N/KB:N/ENG:N/RB:N/AG:N/RU:N",
    )
    server = SamiGPTMCPServer(siem_client=object())
    assert "create_fine_tuning_recommendation" in server.tools
    assert "search_lab_detection_rules" in server.tools

    async def _call(name, arguments):
        return await server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    search = asyncio.run(_call("search_lab_detection_rules", {"query": "encoded powershell"}))
    search_body = json.loads(search["result"]["content"][0]["text"])
    assert search_body["count"] >= 1
    assert search_body["hits"][0]["name"] == "Suspicious PowerShell Encoded Command"

    filed = asyncio.run(
        _call(
            "create_fine_tuning_recommendation",
            {
                "title": "Tune encoded PowerShell",
                "description": "Exclude the signed build-server user.",
                "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            },
        )
    )
    body = json.loads(filed["result"]["content"][0]["text"])
    assert body["informational"] is True
    assert body["status"] == "informational"
    assert "nothing to approve" in body["message"].lower()
    request = queue_service.get_queue().get(body["request_id"])
    assert request.status is RequestStatus.INFORMATIONAL
    assert request.payload["rule_found"] is True
