"""Detection as Code checks, diffs, file writes, and finding status."""

import asyncio
import json
from pathlib import Path

import pytest

from src.ai_controller.approval_queue import init_queue
from src.ai_controller.approval_queue.lab_rules import clear_index_cache
from src.ai_controller.detection.apply import write_exceptions
from src.ai_controller.detection.ask import ask_about_finding
from src.ai_controller.detection.diff import unified_diff
from src.ai_controller.detection.errors import DetectionError
from src.ai_controller.detection.findings import field_rows, suggested_names_for, update_finding_status
from src.ai_controller.detection.review import create_from_fields, implement
from src.ai_controller.detection import rules_store
from src.ai_controller.detection.validation import validate_checked
from src.llm.base import LLMResult


RULE_ID = "4155f6e8-87c8-4551-bfe0-0b8949824858"


def _rule_file(directory: Path) -> Path:
    path = directory / f"[enabled]_pfsense_{RULE_ID}.json"
    path.write_text(json.dumps({
        "_dac": {"status": "enabled", "rule_id": RULE_ID, "name": "pfSense Successful Login"},
        "rule": {
            "name": "pfSense Successful Login",
            "rule_id": RULE_ID,
            "severity": "medium",
            "language": "kuery",
            "enabled": True,
            "query": "event.action:login",
        },
    }), encoding="utf-8")
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


def test_unchecked_conditions_are_not_validated_as_required(rules):
    cards = [
        {"name": "keep", "selected": True, "entries": [{"field": "user.name", "value": "svc"}]},
        {"name": "drop", "selected": False, "entries": [{"field": "host.name", "value": "*"}]},
    ]
    warnings = validate_checked(cards, existing_items=[], evidence_fields=["user.name"])
    assert warnings == ["user.name is a single volatile field. Confirm it is narrow enough."]


def test_wildcard_without_permission_blocks_implement():
    with pytest.raises(DetectionError):
        validate_checked(
            [{"name": "wide", "selected": True, "entries": [{"field": "host.name", "value": "lab*"}]}],
            existing_items=[],
            evidence_fields=["host.name"],
        )


def test_diff_marks_added_exception_lines():
    before = '{\n  "exception_items": []\n}\n'
    after = '{\n  "exception_items": [\n    {"field": "host.name"}\n  ]\n}\n'
    text = unified_diff(before, after, "rule.json")
    assert "+    {\"field\": \"host.name\"}" in text


def test_apply_writes_only_checked_cards(rules):
    path, data, digest = rules_store.load_rule_file(rule_id=RULE_ID)
    cards = [
        {"name": "keep", "selected": True, "entries": [{"field": "host.name", "value": "lab"}]},
        {"name": "drop", "selected": False, "entries": [{"field": "user.name", "value": "root"}]},
    ]
    result = write_exceptions(path, data, cards, digest, RULE_ID)
    written = json.loads(Path(result["file"]).read_text(encoding="utf-8"))
    items = written["exception_items"]
    assert len(items) == 1
    assert items[0]["entries"][0]["field"] == "host.name"
    assert items[0]["entries"][0]["value"] == "lab"


def test_disable_writes_the_disabled_file_before_removing_the_enabled_one(rules):
    from src.ai_controller.detection.apply import write_disabled

    path, data, digest = rules_store.load_rule_file(rule_id=RULE_ID)
    result = write_disabled(path, data, digest)
    written = Path(result["file"])
    assert written.name.startswith("[disabled]_")
    assert written.is_file()
    assert not path.exists()
    body = json.loads(written.read_text(encoding="utf-8"))
    assert body["rule"]["enabled"] is False
    assert body["_dac"]["status"] == "disabled"


def test_suggested_fields_follow_the_rule_and_the_catalog_file(rules):
    rule_path = next(path for path in rules.glob("*.json") if path.name.startswith("[enabled]"))
    data = json.loads(rule_path.read_text(encoding="utf-8"))
    data["rule"]["investigation_fields"] = {"field_names": ["message", "host.name"]}
    rule_path.write_text(json.dumps(data), encoding="utf-8")
    (rules / "suggested_fields.json").write_text(
        json.dumps({"fields": ["user.name", "host.name"]}),
        encoding="utf-8",
    )
    clear_index_cache()
    source = {
        "message": "login ok",
        "host": {"name": "fw"},
        "user": {"name": "admin"},
        "process": {"name": "php-fpm"},
    }
    names = suggested_names_for(source, RULE_ID, "pfSense Successful Login")
    rows = {row["field"]: row["suggested"] for row in field_rows(source, names)}
    assert rows["message"] is True
    assert rows["host.name"] is True
    assert rows["user.name"] is True
    assert rows["process.name"] is False
    from src.ai_controller.approval_queue.lab_rules import search_rules

    assert all(hit.get("name") != "suggested_fields" for hit in search_rules("", limit=50))


def test_field_exception_is_not_written_until_implement(rules):
    from src.ai_controller.detection.review import update_selection

    alert = {"id": "alert-1", "rule_id": RULE_ID, "rule_name": "pfSense Successful Login"}
    created = create_from_fields(
        alert=alert,
        entries=[{"field": "host.name", "value": "lab"}],
    )
    on_disk = json.loads(next(rules.glob("*.json")).read_text(encoding="utf-8"))
    assert "exception_items" not in on_disk
    with pytest.raises(DetectionError):
        implement(created.id)
    from src.ai_controller.detection.review import review_view

    opened = review_view(created)
    assert opened["error"] == ""
    assert opened["exceptions"][0]["selected"] is False
    reviewed = update_selection(created.id, [{"selected": True, "allow_wildcard": False}])
    assert reviewed.payload["dac"]["revisions"][-1]["exceptions"][0]["selected"] is True
    implement(created.id)
    updated = json.loads(next(rules.glob("*.json")).read_text(encoding="utf-8"))
    assert updated["exception_items"][0]["entries"][0]["value"] == "lab"


class _Alerts:
    def __init__(self):
        self.notes = []
        self.closed = []
        self.acknowledged = []

    def search_alert_documents(self, **_kwargs):
        return [
            {"id": "alert-1", "source": {"host": {"name": "lab"}}},
            {"id": "alert-2", "source": {"host": {"name": "other"}}},
        ]

    def add_alert_note(self, alert_id, note):
        self.notes.append((alert_id, note))

    def close_alert(self, alert_id, reason=None, comment=None):
        self.closed.append(alert_id)

    def set_alert_workflow_status(self, alert_id, status):
        self.acknowledged.append((alert_id, status))


def test_close_with_note_and_without_note():
    client = _Alerts()
    entries = [{"field": "host.name", "value": "lab"}]
    without = update_finding_status(
        client, alert_id="alert-1", rule_id=RULE_ID, entries=entries, status="closed", note=""
    )
    assert without["note"] is False
    assert client.notes == []
    assert client.closed == ["alert-1"]
    with_note = update_finding_status(
        client, alert_id="alert-1", rule_id=RULE_ID, entries=entries, status="closed", note="expected login"
    )
    assert with_note["note"] is True
    assert client.notes == [("alert-1", "expected login")]
    ack = update_finding_status(
        client, alert_id="alert-1", rule_id=RULE_ID, entries=entries, status="acknowledged", note=""
    )
    assert ack["note"] is False
    assert client.acknowledged == [("alert-1", "acknowledged")]


def test_ask_records_detection_usage(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMIGPT_USAGE_DIR", str(tmp_path))

    class Provider:
        async def complete(self, prompt, **kwargs):
            assert kwargs.get("mcp_client") is None
            return LLMResult(
                success=True,
                text="This is a successful admin login.",
                model="test-model",
                provider="fake",
                usage={"usage_reported": True, "input_tokens": 4, "output_tokens": 6, "reported_model": "test-model"},
            )

    monkeypatch.setattr("src.ai_controller.detection.ask.get_active_provider", lambda: Provider())
    result = asyncio.run(ask_about_finding(
        prompt_id="ask_about",
        alert={"id": "alert-1", "rule_name": "pfSense", "rule_id": RULE_ID, "severity": "medium", "status": "open"},
        entries=[{"field": "host.name", "value": "lab"}],
    ))
    assert "admin login" in result["answer"]
    ledger = (tmp_path / "usage.jsonl").read_text(encoding="utf-8")
    assert '"session_type":"detection"' in ledger
    assert "detection ask" in ledger
