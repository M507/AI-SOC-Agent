"""Visibility → new_rule DaC: reroute, gate, promote, create file, list_reviews."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.ai_controller.approval_queue import get_queue, init_queue
from src.ai_controller.approval_queue.lab_rules import clear_index_cache
from src.ai_controller.detection.errors import DetectionError
from src.ai_controller.detection import review as review_service
from src.ai_controller.detection.rules_store import create_rule_file
from src.ai_controller.detection.validation import evaluate_new_rule_gate


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


def _visibility_note(**payload_extra):
    queue = get_queue()
    payload = {
        "title": "Missing DNS tunneling detection",
        "description": "Need a query rule for long TXT queries to rare domains.",
        "suggestion": "Need a query rule for long TXT queries to rare domains.",
        "source": "DNS",
        "coverage_check": {
            "likely_gap": True,
            "likely_covered": False,
            "matching_rules": [],
        },
        "engineering": {
            "provider": "github",
            "repository": "acme/lab",
            "issue": {"number": 7, "url": "https://github.com/acme/lab/issues/7", "state": "open"},
        },
    }
    payload.update(payload_extra)
    return queue.create(
        action_type="visibility",
        title="Missing DNS tunneling detection",
        summary="DNS gap",
        rationale="no coverage",
        payload=payload,
        source="mcp",
        created_by="agent",
    )


def _good_new_rule_draft(**overrides):
    draft = {
        "rationale": "No Home Lab rule watches long DNS TXT queries used for tunneling.",
        "safe_to_create": True,
        "overlapping_rule": "",
        "notes": "ok",
        "improvement_plan": ["Detect long TXT queries", "Leave normal DNS alone"],
        "proposed_rule": {
            "name": "Suspicious Long DNS TXT Query",
            "description": "Detect unusually long DNS TXT queries",
            "severity": "medium",
            "risk_score": 47,
            "type": "query",
            "language": "kuery",
            "query": "dns.question.type:TXT and dns.question.name:*",
            "index": ["logs-dns*"],
            "enabled": True,
            "tags": ["dns"],
        },
        "exceptions": [],
    }
    draft.update(overrides)
    return draft


def test_fine_tune_without_rule_reclassifies_to_visibility(rules):
    queue = get_queue()
    created = queue.create(
        action_type="fine_tune",
        title="Something missing",
        summary="no rule",
        payload={
            "title": "Something missing",
            "description": "We need coverage for obscure widget abuse with no existing rule name.",
        },
        source="mcp",
    )
    assert created.action_type == "visibility"
    assert (created.payload or {}).get("reclassified_from") == "fine_tune"
    assert "coverage_check" in (created.payload or {})


def test_fine_tune_with_matching_rule_stays_fine_tune(rules):
    queue = get_queue()
    created = queue.create(
        action_type="fine_tune",
        title="Tune pfSense",
        summary="except lab",
        payload={
            "title": "Tune pfSense",
            "description": "Except lab backup user",
            "rule_id": RULE_ID,
            "rule_name": "pfSense Successful Login",
        },
        source="mcp",
    )
    assert created.action_type == "fine_tune"
    assert created.payload.get("rule_found") is True


def test_migrate_misfiled_fine_tunes_moves_new_rule_intent(rules):
    """Legacy open fine-tunes that ask for a dedicated rule move to Visibility."""
    from src.ai_controller.approval_queue.models import ApprovalRequest, RequestStatus

    queue = get_queue()
    store = queue.store
    # Seed a misfiled note that already has a (wrong) matched rule.
    misfiled = ApprovalRequest(
        action_type="fine_tune",
        title="Add dedicated ntopng.blacklisted rule",
        summary="Create a dedicated detection for blacklist hits",
        rationale="gap",
        risk="low",
        status=RequestStatus.INFORMATIONAL,
        payload={
            "title": "Add dedicated ntopng.blacklisted rule",
            "description": "Add dedicated ntopng.blacklisted rule instead of catch-all",
            "rule_id": RULE_ID,
            "rule_name": "pfSense Successful Login",
            "rule_found": True,
        },
        source="mcp",
    )
    keep = ApprovalRequest(
        action_type="fine_tune",
        title="Add exception for Ubuntu connectivity-check",
        summary="except noise",
        rationale="fp",
        risk="low",
        status=RequestStatus.INFORMATIONAL,
        payload={
            "title": "Add exception for Ubuntu connectivity-check",
            "description": "Add exception for Ubuntu connectivity-check in catch-all",
            "rule_id": RULE_ID,
            "rule_name": "pfSense Successful Login",
            "rule_found": True,
        },
        source="mcp",
    )
    store.put(misfiled)
    store.put(keep)

    result = queue.migrate_misfiled_fine_tunes()
    assert result["reclassified"] >= 1
    assert misfiled.id in result["ids"]

    moved = store.get(misfiled.id)
    assert moved is not None
    assert moved.action_type == "visibility"
    assert (moved.payload or {}).get("reclassified_from") == "fine_tune"
    assert "dedicated" in str((moved.payload or {}).get("reclassified_reason") or "").lower()

    stayed = store.get(keep.id)
    assert stayed is not None
    assert stayed.action_type == "fine_tune"


def test_migrate_misfiled_fine_tunes_moves_missing_rule(rules):
    from src.ai_controller.approval_queue.models import ApprovalRequest, RequestStatus

    queue = get_queue()
    orphan = ApprovalRequest(
        action_type="fine_tune",
        title="Obscure widget abuse",
        summary="no match",
        rationale="gap",
        risk="low",
        status=RequestStatus.INFORMATIONAL,
        payload={
            "title": "Obscure widget abuse",
            "description": "Widget XYZ command abuse with no existing detection name.",
            "rule_found": False,
        },
        source="mcp",
    )
    queue.store.put(orphan)
    result = queue.migrate_misfiled_fine_tunes()
    assert orphan.id in result["ids"]
    moved = queue.store.get(orphan.id)
    assert moved is not None
    assert moved.action_type == "visibility"


def test_evaluate_new_rule_gate_valid():
    gate = evaluate_new_rule_gate(_good_new_rule_draft())
    assert gate["ok"] is True


def test_evaluate_new_rule_gate_missing_fields():
    gate = evaluate_new_rule_gate(
        {
            "safe_to_create": True,
            "rationale": "gap",
            "proposed_rule": {"name": "", "query": "", "type": "query"},
        }
    )
    assert gate["ok"] is False
    joined = " ".join(gate["errors"])
    assert "name" in joined
    assert "query" in joined


def test_evaluate_new_rule_gate_rejects_non_query():
    draft = _good_new_rule_draft()
    draft["proposed_rule"]["type"] = "eql"
    gate = evaluate_new_rule_gate(draft)
    assert gate["ok"] is False
    assert any("query" in err for err in gate["errors"])


def test_evaluate_new_rule_gate_blocks_likely_covered():
    gate = evaluate_new_rule_gate(
        _good_new_rule_draft(),
        coverage_check={
            "likely_covered": True,
            "matching_rules": [{"name": "pfSense Successful Login", "rule_id": RULE_ID}],
        },
    )
    assert gate["ok"] is False
    assert any("already covered" in err for err in gate["errors"])


def test_create_rule_file_writes_enabled_json(rules):
    result = create_rule_file(_good_new_rule_draft()["proposed_rule"])
    path = Path(result["file"])
    assert path.exists()
    assert path.name.startswith("[enabled]_")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["rule"]["type"] == "query"
    assert data["_dac"]["rule_id"] == result["rule_id"]


def test_create_rule_file_collision(rules):
    with pytest.raises(DetectionError, match="already looks like"):
        create_rule_file(
            {
                "name": "pfSense Successful Login",
                "query": "event.action:login and event.outcome:success",
                "severity": "medium",
                "risk_score": 47,
                "type": "query",
                "language": "kuery",
                "index": ["logs-pfsense*"],
            }
        )


def test_promote_visibility_passes_and_lists_reviews(rules, monkeypatch):
    note = _visibility_note()

    async def fake_complete(**kwargs):
        return _good_new_rule_draft()

    monkeypatch.setattr(review_service, "complete_new_rule_draft", fake_complete)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": True, "success": True},
    )

    view = asyncio.run(review_service.promote_visibility_from_request(note.id))
    assert view["stage"] == "drafted"
    assert view["kind"] == "new_rule"
    assert view["proposed_rule"]["query"]
    assert view["diff"]

    reviews = review_service.list_reviews()
    assert any(item.id == note.id for item in reviews)


def test_promote_visibility_blocked_when_likely_covered(rules):
    note = _visibility_note()
    # enrich_visibility rebuilds coverage_check; force a covered result for the gate.
    payload = dict(note.payload or {})
    payload["coverage_check"] = {
        "likely_gap": False,
        "likely_covered": True,
        "matching_rules": [{"name": "pfSense Successful Login", "rule_id": RULE_ID}],
    }
    note.payload = payload
    get_queue().store.put(note)
    with pytest.raises(DetectionError, match="already covered"):
        asyncio.run(review_service.promote_visibility_from_request(note.id))


def test_implement_new_rule_creates_file(rules, monkeypatch):
    note = _visibility_note()

    async def fake_complete(**kwargs):
        return _good_new_rule_draft()

    monkeypatch.setattr(review_service, "complete_new_rule_draft", fake_complete)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": False, "success": True},
    )
    monkeypatch.setattr(
        "src.ai_controller.detection.elastic_sync.push_rule_after_implement",
        lambda client, *, file_path: {
            "synced": True,
            "created": True,
            "file": file_path,
            "file_sha256": "abc",
            "revision": 1,
        },
    )
    monkeypatch.setattr("src.core.elastic_clusters.client_for_id", lambda _cid=None: object())

    asyncio.run(review_service.promote_visibility_from_request(note.id))
    saved = review_service.implement(note.id)
    dac = (saved.payload or {}).get("dac") or {}
    assert dac.get("stage") == "implemented"
    assert Path(dac.get("file") or "").exists()
    assert saved.execution_result.get("created") is True


def test_reject_new_rule_before_implement(rules, monkeypatch):
    note = _visibility_note()

    async def fake_complete(**kwargs):
        return _good_new_rule_draft()

    monkeypatch.setattr(review_service, "complete_new_rule_draft", fake_complete)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": False},
    )
    asyncio.run(review_service.promote_visibility_from_request(note.id))
    rejected = review_service.reject(note.id, comment="not needed")
    dac = (rejected.payload or {}).get("dac") or {}
    assert dac.get("stage") == "rejected"
    assert not list(rules.glob("[enabled]_Suspicious*"))


def test_second_send_updates_same_review(rules, monkeypatch):
    note = _visibility_note(alert_id="alert-1")
    calls = {"n": 0}

    async def fake_complete(**kwargs):
        calls["n"] += 1
        return _good_new_rule_draft()

    monkeypatch.setattr(review_service, "complete_new_rule_draft", fake_complete)
    monkeypatch.setattr(
        get_queue(),
        "delete_linked_github_issue",
        lambda request, *, comment: {"attempted": True, "success": True},
    )
    first = asyncio.run(review_service.promote_visibility_from_request(note.id))
    second = asyncio.run(review_service.promote_visibility_from_request(note.id))
    assert first["id"] == second["id"]
    assert second["stage"] == "drafted"
    # Second call short-circuits when already drafted+passed.
    assert calls["n"] == 1
