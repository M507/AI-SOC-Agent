import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

from src.ai_controller.agent_executor import ExecutionResult
from src.ai_controller.session_manager import SessionManager
from src.ai_controller.web import server as web_server


def test_reenable_starts_immediate_fresh_schedule(tmp_path):
    manager = SessionManager(str(tmp_path))
    autorun = manager.create_autorun("test", "triage alerts", 300)

    manager.update_autorun(autorun.id, enabled=False)
    assert autorun.enabled is False
    assert autorun.next_run is None

    before = datetime.now()
    manager.update_autorun(autorun.id, enabled=True)
    after = datetime.now()

    assert autorun.enabled is True
    assert before <= autorun.next_run <= after


def test_editing_disabled_autorun_does_not_restore_stale_timer(tmp_path):
    manager = SessionManager(str(tmp_path))
    autorun = manager.create_autorun("test", "triage alerts", 300)
    autorun.enabled = False
    assert autorun.next_run is not None

    manager.update_autorun(autorun.id, name="renamed")

    assert autorun.next_run is None


def test_editing_enabled_interval_starts_new_timer_from_save(tmp_path):
    manager = SessionManager(str(tmp_path))
    autorun = manager.create_autorun("test", "triage alerts", 300)

    before = datetime.now() + timedelta(seconds=55)
    after = datetime.now() + timedelta(seconds=65)
    manager.update_autorun(autorun.id, interval_seconds=60)

    assert autorun.interval_seconds == 60
    assert before <= autorun.next_run <= after


def test_editing_autorun_settings_persists_and_updates_session_cluster(tmp_path):
    manager = SessionManager(str(tmp_path))
    autorun = manager.create_autorun("old", "old prompt", 300, cluster_id="old-cluster")

    manager.update_autorun(
        autorun.id,
        name="new",
        command="new prompt",
        condition_function="get_recent_alerts",
        cluster_id="new-cluster",
    )

    restored = SessionManager(str(tmp_path)).get_autorun(autorun.id)
    session = manager.get_session(autorun.session_id)
    assert restored.name == "new"
    assert restored.command == "new prompt"
    assert restored.condition_function == "get_recent_alerts"
    assert restored.cluster_id == "new-cluster"
    assert session.cluster_id == "new-cluster"


def test_run_autorun_with_existing_session_and_condition(tmp_path, monkeypatch):
    """Regression: persistent session_id must not leave session_name unbound."""
    manager = SessionManager(str(tmp_path))
    autorun = manager.create_autorun(
        "t1",
        "triage now",
        5,
        condition_function="get_recent_alerts 1",
        cluster_id="lab-88-es",
    )
    assert autorun.session_id
    session = manager.get_session(autorun.session_id)
    assert session is not None

    condition_calls = []

    async def fake_condition(condition_function, executor, **kwargs):
        condition_calls.append(kwargs)
        return True, {
            "evaluation": "ok",
            "output": {"uninvestigated_alerts": 1},
            "command_executed": "python:get_recent_alerts",
        }

    async def fake_execute_command(command, **kwargs):
        return ExecutionResult(success=True, output={"text": "done"}, timestamp=datetime.now())

    executor = AsyncMock()
    executor.execute_command = AsyncMock(side_effect=fake_execute_command)

    monkeypatch.setattr(web_server, "session_manager", manager)
    monkeypatch.setattr(web_server, "executor", executor)
    monkeypatch.setattr(web_server, "_check_autorun_condition", fake_condition)
    monkeypatch.setattr(web_server, "broadcast_to_session", AsyncMock())
    monkeypatch.setattr(web_server, "UI_DEBUG_MODE", False)

    asyncio.run(web_server._run_autorun(autorun))

    assert condition_calls, "condition check should run on the existing-session path"
    assert condition_calls[0]["session_name"] == session.name
    assert condition_calls[0]["session_id"] == session.id
    executor.execute_command.assert_awaited_once()
    refreshed = manager.get_session(autorun.session_id)
    commands = [entry.command for entry in refreshed.entries]
    assert any(entry.startswith("[CONDITION CHECK]") for entry in commands)
    assert "triage now" in commands
