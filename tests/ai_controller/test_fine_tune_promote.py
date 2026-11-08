"""Fine-tune → DaC promote: prompts, validation loop, GitHub delete."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import pytest

from src.ai_controller.approval_queue import get_queue, init_queue
from src.ai_controller.approval_queue.lab_rules import clear_index_cache
from src.ai_controller.detection.drafting import normalize_suggestions
from src.ai_controller.detection.errors import DetectionError
from src.ai_controller.detection.prompts import DRAFT_SYSTEM, build_draft_prompt
from src.ai_controller.detection import review as review_service
from src.ai_controller.detection.validation import evaluate_draft_gate, validate_draft_regression


RULE_ID = "4155f6e8-87c8-4551-bfe0-0b8949824858"


def _rule_file(directory: Path) -> Path:
    path = directory / f"[enabled]_pfsense_{RULE_ID}.json"
    path.write_text(
        json.dumps(
            {
                "_dac": {"status": "enabled", "rule_id": RULE_ID, "name": "pfSense Successful Login"},
                "rule": {
                    "name": "pfSense Successful Login",
                    "rule_id": RULE_ID,
                    "severity": "medium",
                    "language": "kuery",
                    "type": "query",
                    "enabled": True,
                    "query": "event.action:login and event.outcome:success",
                    "index": ["logs-pfsense*"],
                },
                "exception_items": [],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def rules(tmp_path, monkeypatch):
    folder = tmp_path / "rules"
    folder.mkdir()
    _rule_file(folder)
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(folder))
    clear_index_cache()
    init_queue(str(tmp_path / "queue"))
    return folder


def _fine_tune_note(**payload_extra):
    queue = get_queue()
    payload = {
        "title": "Tune pfSense login",
        "description": "Except the lab firewall admin host when user is svc-backup.",
        "suggestion": "Except the lab firewall admin host when user is svc-backup.",
        "rule_id": RULE_ID,
        "rule_name": "pfSense Successful Login",
        "engineering": {
            "provider": "github",
            "repository": "acme/lab",
            "issue": {"number": 42, "url": "https://github.com/acme/lab/issues/42", "state": "open"},
        },
    }
    payload.update(payload_extra)
    return queue.create(
        action_type="fine_tune",
        title="Tune pfSense login",
        summary="Except lab admin host",
        rationale="noise",
        payload=payload,
        source="mcp",
        created_by="agent",
    )


def test_draft_system_mentions_siem_and_json_only():
    assert "Elastic" in DRAFT_SYSTEM
    assert "never invent" in DRAFT_SYSTEM.lower() or "Never invent" in DRAFT_SYSTEM
    assert "JSON only" in DRAFT_SYSTEM
    assert "improvement_plan" in DRAFT_SYSTEM
    assert "siem_context" in DRAFT_SYSTEM


def test_build_draft_prompt_includes_suggestion_and_rule(rules):
    rule_file = json.loads(next(rules.glob("*.json")).read_text(encoding="utf-8"))
    prompt = build_draft_prompt(
        rule_file=rule_file,
        alerts=[],
        suggestion="Except host fw-lab-01 for user svc-backup",
        suggestion_title="Tune pfSense",
        cluster_id="lab-1",
    )
    assert "Except host fw-lab-01" in prompt
    assert "Tune pfSense" in prompt
    assert "event.action:login" in prompt
    assert "siem_environment" in prompt
    assert "actual_rule" in prompt
    assert "Do not invent" in prompt or "do not invent" in prompt


def test_build_draft_prompt_includes_analyst_instructions(rules):
    rule_file = json.loads(next(rules.glob("*.json")).read_text(encoding="utf-8"))
    prompt = build_draft_prompt(
        rule_file=rule_file,
        alerts=[],
        suggestion="Except lab noise",
        analyst_instructions="focus on host X; ignore other noise",
    )
    assert '"analyst_instructions"' in prompt
    assert "focus on host X; ignore other noise" in prompt
    assert "binding focus constraints" in prompt
    assert "analyst_instructions" in DRAFT_SYSTEM


def test_normalize_suggestions_keeps_enriched_fields():
    normalized = normalize_suggestions(
        {
            "rationale": "Elastic login noise from backup.",
            "safe_to_except": True,
            "siem_context": {
                "platform": "elastic",
                "rule_type": "query",
                "signal_summary": "Successful VPN/firewall logins",
                "data_sources": ["logs-pfsense*"],
            },
            "rule_understanding": "Matches successful login events.",
            "improvement_plan": ["Except svc-backup on fw-lab-01", "Other logins still fire"],
            "exceptions": [
                {
                    "name": "lab backup",
                    "confidence": "high",
                    "entries": [
                        {"field": "host.name", "value": "fw-lab-01"},
                        {"field": "user.name", "value": "svc-backup"},
                    ],
                }
            ],
            "notes": "Revisit if backup host changes.",
        }
    )
    assert normalized["siem_context"]["signal_summary"]
    assert normalized["improvement_plan"][0].startswith("Except")
    assert normalized["exceptions"][0]["selected"] is True


def test_regression_gate_rejects_volatile_only_and_empty_teaching():
    errors = validate_draft_regression(
        {
            "safe_to_except": True,
            "rationale": "",
            "improvement_plan": [],
            "exceptions": [
                {"entries": [{"field": "source.ip", "value": "1.2.3.4"}]},
            ],
        },
        diff_text="+ something",
    )
    assert any("volatile" in err.lower() for err in errors)
    assert any("rationale" in err.lower() or "improvement" in err.lower() for err in errors)


def test_evaluate_draft_gate_passes_narrow_exception():
    revision = {
        "safe_to_except": True,
        "rationale": "Elastic pfSense login noise from the lab backup account.",
        "rule_understanding": "Successful login query on pfSense logs.",
        "improvement_plan": ["Except host+user pair", "Other admins still alert"],
        "exceptions": [
            {
                "name": "lab backup",
                "selected": True,
                "entries": [
                    {"field": "host.name", "value": "fw-lab-01"},
                    {"field": "user.name", "value": "svc-backup"},
                ],
            }
        ],
    }
    gate = evaluate_draft_gate(revision, existing_items=[], evidence_fields=[], diff_text="+ exception")
    assert gate["ok"] is True


def test_promote_passes_analyst_note_to_draft(rules, monkeypatch):
    note = _fine_tune_note()
    seen = {"instructions": None}

    async def fake_complete_draft(**kwargs):
        seen["instructions"] = kwargs.get("analyst_instructions")
        return {
            "rationale": "Elastic pfSense successful-login noise from the lab backup job.",
            "safe_to_except": True,
            "siem_context": {
                "platform": "elastic",
                "rule_type": "query",
                "signal_summary": "Successful firewall logins",
                "data_sources": ["logs-pfsense*"],
            },
            "rule_understanding": "Kuery match on successful login.",
            "improvement_plan": ["Except host+user", "Other logins remain"],
            "exceptions": [
                {
                    "name": "lab backup",
                    "confidence": "high",
                    "entries": [
                        {"field": "host.name", "value": "fw-lab-01"},
                        {"field": "user.name", "value": "svc-backup"},
                    ],
                    "selected": True,
                    "allow_wildcard": False,
                }
            ],
            "notes": "ok",
        }

    monkeypatch.setattr(review_service, "complete_draft", fake_complete_draft)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": True, "success": True},
    )

    view = asyncio.run(
        review_service.promote_from_request(note.id, analyst_note="focus on host X")
    )
    assert seen["instructions"] == "focus on host X"
    assert view["analyst_instructions"] == "focus on host X"
    stored = get_queue().get(note.id)
    assert (stored.payload or {}).get("analyst_instructions") == "focus on host X"
    assert ((stored.payload or {}).get("dac") or {}).get("analyst_instructions") == "focus on host X"


def test_promote_passes_on_first_attempt_and_deletes_github(rules, monkeypatch):
    note = _fine_tune_note()
    deleted = {"n": 0}

    async def fake_complete_draft(**kwargs):
        assert "Except the lab firewall" in (kwargs.get("suggestion") or "")
        return {
            "rationale": "Elastic pfSense successful-login noise from the lab backup job.",
            "safe_to_except": True,
            "siem_context": {
                "platform": "elastic",
                "rule_type": "query",
                "signal_summary": "Successful firewall logins",
                "data_sources": ["logs-pfsense*"],
            },
            "rule_understanding": "Kuery match on successful login.",
            "improvement_plan": ["Except host+user", "Other logins remain"],
            "exceptions": [
                {
                    "name": "lab backup",
                    "confidence": "high",
                    "entries": [
                        {"field": "host.name", "value": "fw-lab-01"},
                        {"field": "user.name", "value": "svc-backup"},
                    ],
                    "selected": True,
                    "allow_wildcard": False,
                }
            ],
            "notes": "ok",
        }

    def fake_delete(request, *, comment):
        deleted["n"] += 1
        payload = dict(request.payload or {})
        eng = dict(payload.get("engineering") or {})
        issue = dict(eng.get("issue") or {})
        issue["deleted"] = True
        issue["state"] = "deleted"
        eng["issue"] = issue
        payload["engineering"] = eng
        request.payload = payload
        return {"attempted": True, "success": True, "issue": {"number": 42, "deleted": True}}

    monkeypatch.setattr(review_service, "complete_draft", fake_complete_draft)
    monkeypatch.setattr(get_queue(), "delete_linked_github_issue", fake_delete)

    view = asyncio.run(review_service.promote_from_request(note.id))
    assert view["stage"] == "drafted"
    assert view["diff"]
    assert view["exceptions"]
    assert all(card.get("selected") is not False for card in view["exceptions"])
    assert view["auto_fix"]["passed"] is True
    assert deleted["n"] == 1
    assert view["github"]["success"] is True


def test_promote_retries_then_passes(rules, monkeypatch):
    note = _fine_tune_note()
    calls = {"n": 0}

    async def flaky_complete_draft(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "rationale": "",
                "safe_to_except": True,
                "exceptions": [
                    {
                        "name": "bad",
                        "confidence": "high",
                        "entries": [{"field": "source.ip", "value": "10.0.0.1"}],
                        "selected": True,
                        "allow_wildcard": False,
                    }
                ],
                "notes": "",
                "improvement_plan": [],
            }
        return {
            "rationale": "Elastic pfSense login noise narrowed by host and user.",
            "safe_to_except": True,
            "siem_context": {"platform": "elastic", "rule_type": "query", "signal_summary": "logins", "data_sources": []},
            "rule_understanding": "Successful login query.",
            "improvement_plan": ["Except host+user", "Keep other alerts"],
            "exceptions": [
                {
                    "name": "lab backup",
                    "confidence": "high",
                    "entries": [
                        {"field": "host.name", "value": "fw-lab-01"},
                        {"field": "user.name", "value": "svc-backup"},
                    ],
                    "selected": True,
                    "allow_wildcard": False,
                }
            ],
            "notes": "ok",
        }

    monkeypatch.setattr(review_service, "complete_draft", flaky_complete_draft)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": True, "success": True},
    )

    view = asyncio.run(review_service.promote_from_request(note.id))
    assert calls["n"] == 2
    assert view["stage"] == "drafted"
    assert view["auto_fix"]["passed_on_attempt"] == 2
    assert len(view["auto_fix"]["attempts"]) == 2


def test_promote_exhausts_three_tries_without_github_delete(rules, monkeypatch):
    note = _fine_tune_note()
    deleted = {"n": 0}

    async def always_bad(**kwargs):
        return {
            "rationale": "",
            "safe_to_except": True,
            "exceptions": [
                {
                    "name": "bad",
                    "confidence": "high",
                    "entries": [{"field": "source.ip", "value": "10.0.0.1"}],
                    "selected": True,
                    "allow_wildcard": False,
                }
            ],
            "notes": "",
            "improvement_plan": [],
        }

    monkeypatch.setattr(review_service, "complete_draft", always_bad)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: deleted.__setitem__("n", deleted["n"] + 1) or {"attempted": True, "success": True},
    )

    view = asyncio.run(review_service.promote_from_request(note.id))
    assert view["stage"] == "needs_fix"
    assert view["auto_fix"]["exhausted"] is True
    assert len(view["auto_fix"]["attempts"]) == 3
    assert deleted["n"] == 0


def test_acknowledge_fine_tune_deletes_github(rules, monkeypatch):
    note = _fine_tune_note()
    calls = {"n": 0}

    def fake_delete(request, *, comment):
        calls["n"] += 1
        payload = dict(request.payload or {})
        eng = dict(payload.get("engineering") or {})
        issue = dict(eng.get("issue") or {})
        issue["deleted"] = True
        issue["state"] = "deleted"
        eng["issue"] = issue
        payload["engineering"] = eng
        request.payload = payload
        return {"attempted": True, "success": True, "issue": {"number": 42, "deleted": True}}

    monkeypatch.setattr(get_queue(), "delete_linked_github_issue", fake_delete)
    updated = get_queue().acknowledge(note.id, comment="done")
    assert updated.status.value == "acknowledged"
    assert calls["n"] == 1
    assert (updated.payload.get("engineering") or {}).get("issue", {}).get("deleted") is True


def test_promote_missing_rule_does_not_call_model(tmp_path, monkeypatch):
    folder = tmp_path / "empty-rules"
    folder.mkdir()
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(folder))
    clear_index_cache()
    init_queue(str(tmp_path / "queue2"))
    note = get_queue().create(
        action_type="fine_tune",
        title="Missing",
        summary="no rule",
        rationale="x",
        payload={
            "title": "Missing",
            "description": "tune nothing",
            "rule_name": "does-not-exist",
        },
        source="mcp",
        created_by="agent",
    )
    called = {"n": 0}

    async def boom(**kwargs):
        called["n"] += 1
        raise AssertionError("model should not run")

    monkeypatch.setattr(review_service, "complete_draft", boom)
    with pytest.raises(DetectionError):
        asyncio.run(review_service.promote_from_request(note.id))
    assert called["n"] == 0
