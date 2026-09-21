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
