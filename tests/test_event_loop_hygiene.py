"""Event-loop hygiene: MCP offload, progress debounce, autorun next_run-from-start."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from src.ai_controller.agent_executor import ExecutionResult
from src.ai_controller.session_manager import SessionManager, SessionType
from src.ai_controller.web import server as web_server
from src.mcp.cluster_context import (
    get_elastic_cluster_id,
    get_session_id,
    run_with_bound_context,
)


def test_run_with_bound_context_sets_contextvars_on_worker_thread():
    seen = {}

    def worker():
        seen["thread"] = threading.current_thread().name
        seen["cluster"] = get_elastic_cluster_id()
        seen["session"] = get_session_id()
        return "ok"

    result = run_with_bound_context("lab-cluster", "sess-1", worker)
    assert result == "ok"
    assert seen["cluster"] == "lab-cluster"
    assert seen["session"] == "sess-1"
    assert get_elastic_cluster_id() is None
    assert get_session_id() is None


def test_mcp_execute_tool_offloads_to_thread_with_context(monkeypatch):
    from src.mcp.mcp_server import SamiGPTMCPServer
    from src.mcp import cluster_context

    server = object.__new__(SamiGPTMCPServer)
    observed = {}

    def fake_sync(self, tool_name, args):
        observed["thread"] = threading.current_thread().name
        observed["cluster"] = cluster_context.get_elastic_cluster_id()
        observed["session"] = cluster_context.get_session_id()
        observed["tool"] = tool_name
        return {"ok": True, "tool": tool_name}

    monkeypatch.setattr(SamiGPTMCPServer, "_execute_tool_sync", fake_sync)

    async def _run():
        cluster_context.set_elastic_cluster_id("c-1")
        cluster_context.set_session_id("s-1")
        try:
            return await SamiGPTMCPServer._execute_tool(server, "lookup_entity", {"q": "x"})
        finally:
            cluster_context.set_elastic_cluster_id(None)
            cluster_context.set_session_id(None)

    result = asyncio.run(_run())
    assert result == {"ok": True, "tool": "lookup_entity"}
    assert observed["cluster"] == "c-1"
    assert observed["session"] == "s-1"
    assert observed["tool"] == "lookup_entity"
    assert "MainThread" not in observed["thread"]


def test_progress_update_debounces_disk_writes(tmp_path, monkeypatch):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("s1", SessionType.MANUAL)
    entry = manager.add_entry(session.id, "run triage")

    saves = {"count": 0}
    original = manager._save_session

    def counting_save(sess):
        saves["count"] += 1
        original(sess)

    monkeypatch.setattr(manager, "_save_session", counting_save)
    monkeypatch.setattr(web_server, "session_manager", manager)
    monkeypatch.setattr(web_server, "broadcast_to_session", AsyncMock())
    web_server._progress_flush_tasks.clear()
    saves["count"] = 0

    on_progress = web_server._live_progress(session.id, entry.id)

    async def _burst():
        for i in range(5):
            await on_progress([{"step": i}])
        # In-memory updates only; debounce not fired yet
        assert saves["count"] == 0
        await asyncio.sleep(web_server._PROGRESS_FLUSH_DELAY_S + 0.25)
        assert saves["count"] >= 1
        count_after_debounce = saves["count"]
        await web_server._flush_progress_now(session.id)
        # Final flush writes at most once more
        assert saves["count"] <= count_after_debounce + 1

    asyncio.run(_burst())
    assert saves["count"] <= 3


def test_autorun_schedules_next_run_from_start(tmp_path, monkeypatch):
    manager = SessionManager(str(tmp_path))
    interval = 10
    autorun = manager.create_autorun(
        "t1",
        "triage now",
        interval,
        condition_function="get_recent_alerts 1",
        cluster_id="lab-88-es",
    )

    async def fake_condition(condition_function, executor, **kwargs):
        return True, {
            "evaluation": "ok",
            "output": {"uninvestigated_alerts": 1},
            "command_executed": "python:get_recent_alerts",
        }

    async def fake_execute_command(command, **kwargs):
        # Long enough that start+interval and completion+interval diverge.
        await asyncio.sleep(2.5)
        return ExecutionResult(success=True, output={"text": "done"}, timestamp=datetime.now())

    executor = AsyncMock()
    executor.parse_command = MagicMock(return_value=MagicMock())
    executor.execute_command = AsyncMock(side_effect=fake_execute_command)

    monkeypatch.setattr(web_server, "session_manager", manager)
    monkeypatch.setattr(web_server, "executor", executor)
    monkeypatch.setattr(web_server, "_check_autorun_condition", fake_condition)
    monkeypatch.setattr(web_server, "broadcast_to_session", AsyncMock())
    monkeypatch.setattr(web_server, "UI_DEBUG_MODE", False)
    web_server.autorun_execute_semaphore = asyncio.Semaphore(1)
    web_server.running_autoruns.clear()

    before = datetime.now()
    asyncio.run(web_server._run_autorun(autorun))
    after = datetime.now()

    refreshed = manager.get_autorun(autorun.id)
    assert refreshed.next_run is not None
    # next_run ≈ start+interval, not completion+interval
    start_based = before + timedelta(seconds=interval)
    completion_based = after + timedelta(seconds=interval)
    assert abs((refreshed.next_run - start_based).total_seconds()) < 2.0
    assert refreshed.next_run < completion_based - timedelta(seconds=1.5)
    executor.execute_command.assert_awaited_once()


def test_autorun_execute_semaphore_serializes_llm_runs(tmp_path, monkeypatch):
    manager = SessionManager(str(tmp_path))
    a1 = manager.create_autorun("a1", "triage one", 300, cluster_id="lab")
    a2 = manager.create_autorun("a2", "triage two", 300, cluster_id="lab")

    active = {"n": 0, "peak": 0}

    async def fake_execute_command(command, **kwargs):
        active["n"] += 1
        active["peak"] = max(active["peak"], active["n"])
        await asyncio.sleep(0.15)
        active["n"] -= 1
        return ExecutionResult(success=True, output={"text": "done"}, timestamp=datetime.now())

    executor = AsyncMock()
    executor.parse_command = MagicMock(return_value=MagicMock())
    executor.execute_command = AsyncMock(side_effect=fake_execute_command)

    monkeypatch.setattr(web_server, "session_manager", manager)
    monkeypatch.setattr(web_server, "executor", executor)
    monkeypatch.setattr(web_server, "broadcast_to_session", AsyncMock())
    monkeypatch.setattr(web_server, "UI_DEBUG_MODE", False)
    web_server.autorun_execute_semaphore = asyncio.Semaphore(1)
    web_server.running_autoruns.clear()

    async def _both():
        await asyncio.gather(
            web_server._run_autorun(a1),
            web_server._run_autorun(a2),
        )

    asyncio.run(_both())
    assert active["peak"] == 1
    assert executor.execute_command.await_count == 2


def test_autorun_condition_get_recent_alerts_uses_to_thread(monkeypatch):
    calls = {"to_thread": 0}
    real_to_thread = asyncio.to_thread

    async def tracking_to_thread(fn, *args, **kwargs):
        calls["to_thread"] += 1
        return await real_to_thread(fn, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", tracking_to_thread)

    monkeypatch.setattr(
        "src.core.elastic_clusters.client_for_id",
        lambda cluster_id=None: object(),
    )

    def fake_get_recent_alerts(**kwargs):
        return {"uninvestigated_alerts": 0, "groups": []}

    import src.orchestrator.tools_siem as tools_siem

    monkeypatch.setattr(tools_siem, "get_recent_alerts", fake_get_recent_alerts)

    async def _run():
        return await web_server._check_autorun_condition(
            "get_recent_alerts hours_back=1 limit=1",
            executor=MagicMock(),
            cluster_id="lab",
        )

    ok, details = asyncio.run(_run())
    assert calls["to_thread"] >= 1
    assert details.get("execution_success") is True
    assert ok is False  # no uninvestigated alerts
