from datetime import datetime, timedelta

from src.ai_controller.session_manager import SessionManager


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
