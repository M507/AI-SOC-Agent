"""Safety policy and cleanup behavior for integration skill smoke tests."""

import asyncio

from src.ai_controller.web import integration_skill_tests as probes


def test_every_integration_skill_has_inventory_policy():
    for integration_id in ("iris", "thehive", "elastic:example", "edr", "cti", "netbox", "engineering"):
        skills = probes.skills_for_integration(integration_id)
        inventory = probes.skill_inventory(integration_id)
        assert skills
        assert [item["id"] for item in inventory] == skills
        assert all(item["mode"] in {"read", "create_cleanup", "skip"} for item in inventory)


def test_critical_skills_are_never_runnable():
    for integration_id, skill in (
        ("edr", "isolate_endpoint"),
        ("edr", "kill_process_on_endpoint"),
        ("elastic:example", "close_alert"),
        ("elastic:example", "update_alert_verdict"),
        ("elastic:example", "isolate_endpoint"),
        ("elastic:example", "release_endpoint_isolation"),
    ):
        item = next(entry for entry in probes.skill_inventory(integration_id) if entry["id"] == skill)
        assert item["mode"] == "skip"
        assert "destructive" in item["skip_reason"].lower()


def test_case_resource_is_deleted_when_skill_fails(monkeypatch):
    deleted = []

    async def fake_create(_context):
        return "case-123", {"success": True, "case_id": "case-123"}

    async def fake_execute(_server, skill, _args):
        assert skill == "add_case_comment"
        raise RuntimeError("dummy write failed")

    async def fake_delete(_context, case_id):
        deleted.append(case_id)
        return {"attempted": True, "ok": True, "message": "deleted"}

    monkeypatch.setattr(probes, "_create_case_fixture", fake_create)
    monkeypatch.setattr(probes, "_execute", fake_execute)
    monkeypatch.setattr(probes, "_delete_case", fake_delete)

    context = probes.ProbeContext("iris", server=object(), client=object())
    result = asyncio.run(probes.test_skill(context, "add_case_comment"))
    assert result["status"] == "failed"
    assert deleted == ["case-123"]
    assert result["cleanup"]["ok"] is True


def test_cleanup_failure_makes_creation_test_fail(monkeypatch):
    async def fake_create(_context):
        return "case-456", {"success": True, "case_id": "case-456"}

    async def fake_delete(_context, _case_id):
        return {"attempted": True, "ok": False, "message": "delete rejected"}

    monkeypatch.setattr(probes, "_create_case_fixture", fake_create)
    monkeypatch.setattr(probes, "_delete_case", fake_delete)

    context = probes.ProbeContext("iris", server=object(), client=object())
    result = asyncio.run(probes.test_skill(context, "create_case"))
    assert result["status"] == "failed"
    assert result["cleanup"]["ok"] is False
    assert "cleanup failed" in result["message"].lower()


def test_local_tip_skill_reuses_existing_hash(monkeypatch):
    seen = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return [{"value": "a" * 64}]

    class Http:
        base_url = "http://tip.test"
        timeout_seconds = 5
        verify_ssl = False

    class Client:
        _http = Http()

    Client.__name__ = "LocalTipCTIClient"

    monkeypatch.setattr(probes.requests, "get", lambda *args, **kwargs: Response())

    async def fake_execute(_server, skill, args):
        seen["skill"] = skill
        seen["hash"] = args["hash_value"]
        return {"success": True}

    monkeypatch.setattr(probes, "_execute", fake_execute)
    context = probes.ProbeContext("cti", server=object(), client=Client())
    result = asyncio.run(probes.test_skill(context, "lookup_hash_ti"))
    assert result["status"] == "passed"
    assert seen == {"skill": "lookup_hash_ti", "hash": "a" * 64}
    assert "no test indicator was created" in result["message"].lower()
