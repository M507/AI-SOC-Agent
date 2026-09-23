"""Tests for informational runbook-gap recommendations."""

from src.ai_controller.approval_queue.catalog import get_action_spec, spec_for_mcp_tool
from src.ai_controller.approval_queue.runbook_gaps import enrich_runbook_gap, list_case_runbooks
from src.core.skill_vector import SKILL_TO_SOLUTIONS, human_skill_label
from src.mcp.mcp_server import SamiGPTMCPServer


def test_runbook_gap_action_is_informational_and_gated():
    spec = get_action_spec("runbook_gap")
    assert spec is not None
    assert spec.execution == "informational"
    assert spec.gated_mcp_tool == "create_runbook_recommendation"
    assert spec_for_mcp_tool("create_runbook_recommendation") is spec


def test_create_runbook_recommendation_is_rb_skill():
    assert SKILL_TO_SOLUTIONS["create_runbook_recommendation"] == ("RB",)
    assert human_skill_label("create_runbook_recommendation") == "File a runbook-gap note"


def test_list_case_runbooks_finds_soc1_cases():
    cases = list_case_runbooks("soc1")
    names = {item["name"] for item in cases}
    assert "suspicious_login_triage" in names
    assert "malware_initial_triage" in names


def test_enrich_runbook_gap_flags_possible_match_for_login():
    enriched = enrich_runbook_gap(
        {
            "title": "Need case runbook: Suspicious Login",
            "description": "Playbook for suspicious login triage with user and source IP checks.",
            "rule_name": "Suspicious Login",
            "alert_type": "suspicious login",
            "soc_tier": "soc1",
        }
    )
    assert enriched["coverage_check"]["case_runbook_count"] >= 2
    assert enriched["near_matches"]
    assert enriched["coverage_check"]["status"] in {"possible_match", "likely_gap"}
    assert any("login" in m["path"] for m in enriched["near_matches"])


def test_enrich_runbook_gap_suggests_path_for_unknown_type():
    enriched = enrich_runbook_gap(
        {
            "title": "Need case runbook: Quantum Widget Abuse",
            "description": "No existing playbook covers quantum widget abuse on OT hosts.",
            "rule_name": "Quantum Widget Abuse",
            "soc_tier": "soc1",
        }
    )
    assert enriched["coverage_check"]["status"] == "likely_gap"
    assert enriched.get("suggested_path", "").startswith("soc1/cases/")


def test_mcp_registers_create_runbook_recommendation():
    server = SamiGPTMCPServer()
    assert "create_runbook_recommendation" in server.tools
    schema = server.tools["create_runbook_recommendation"]["inputSchema"]
    assert "title" in schema["properties"]
    assert "description" in schema["properties"]


def test_save_case_runbook_writes_under_cases(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue.create_runbook import (
        normalize_case_runbook_path,
        save_case_runbook,
    )

    monkeypatch.setenv("SAMI_RUNBOOKS_DIR", str(tmp_path))
    assert normalize_case_runbook_path(
        None, rule_name="Impossible Travel!", soc_tier="soc1"
    ) == "soc1/cases/impossible_travel_triage"

    content = "# SOC1: Impossible Travel Triage Runbook\n\n## Objective\nTriage travel alerts.\n"
    result = save_case_runbook("soc1/cases/impossible_travel_triage", content)
    assert result["success"] is True
    written = tmp_path / "soc1" / "cases" / "impossible_travel_triage.md"
    assert written.is_file()
    assert "Impossible Travel" in written.read_text(encoding="utf-8")

    blocked = save_case_runbook("../etc/passwd", content)
    assert blocked["success"] is False

    duplicate = save_case_runbook("soc1/cases/impossible_travel_triage", content)
    assert duplicate["success"] is False


def test_build_create_runbook_prompt_includes_alert_and_path():
    from src.ai_controller.approval_queue.create_runbook import build_create_runbook_prompt
    from src.ai_controller.approval_queue.models import ApprovalRequest, RequestStatus

    request = ApprovalRequest(
        id="req-1",
        action_type="runbook_gap",
        title="Need case runbook: Impossible Travel",
        summary="Missing playbook",
        rationale="Used only generic triage",
        status=RequestStatus.INFORMATIONAL,
        payload={
            "title": "Need case runbook: Impossible Travel",
            "description": "Author a travel-specific playbook with GeoIP checks.",
            "rule_name": "Impossible Travel",
            "alert_type": "impossible travel",
            "alert_id": "alert-99",
            "suggested_path": "soc1/cases/impossible_travel_triage",
            "alert": {"id": "alert-99", "title": "Impossible Travel", "severity": "high"},
            "investigation_summary": "Closed as BTP after VPN check.",
        },
    )
    built = build_create_runbook_prompt(request)
    assert built["target_path"] == "soc1/cases/impossible_travel_triage"
    assert "save_case_runbook" in built["prompt"]
    assert "alert-99" in built["prompt"]
    assert "Impossible Travel" in built["prompt"]
    assert "get_alert_notes" in built["prompt"]


def test_mcp_registers_save_case_runbook():
    server = SamiGPTMCPServer()
    assert "save_case_runbook" in server.tools
    assert SKILL_TO_SOLUTIONS["save_case_runbook"] == ("RB",)
    assert human_skill_label("save_case_runbook") == "Save a case runbook file"
