"""Reports are completed manual-session replies."""

from fastapi.testclient import TestClient

from src.ai_controller.web import auth as auth_mod
from src.ai_controller.web.auth import COOKIE_NAME, SessionManagerAuth, WebAuthConfig, _login_failures, _sessions, hash_password
from src.ai_controller.web import server as web_server
from src.ai_controller.web.server import app, initialize


def _client(tmp_path):
    _sessions.clear()
    _login_failures.clear()
    initialize(
        config_storage_dir=str(tmp_path),
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    auth_mod._auth = SessionManagerAuth(
        WebAuthConfig(
            username="admin",
            password=hash_password("test-password"),
            session_secret="test-session-secret-value-minimum-32-chars-long",
            session_ttl_seconds=43200,
            cookie_secure=True,
        )
    )
    client = TestClient(app, base_url="https://testserver")
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    assert login.status_code == 200
    assert COOKIE_NAME in client.cookies
    return client


def test_reports_list_finished_replies_and_skip_errors(tmp_path):
    client = _client(tmp_path)
    session = web_server.session_manager.create_session("Account creation")
    web_server.session_manager.add_entry(
        session.id,
        "investigate the failure",
        result={"success": False, "error": "timeout", "output": {"text": "should stay hidden"}},
    )
    finished = web_server.session_manager.add_entry(
        session.id,
        "investigate this alert",
        result={"success": True, "output": {"text": "**True positive.** The account was created."}},
    )

    listed = client.get("/api/reports")
    assert listed.status_code == 200, listed.text
    reports = listed.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["entry_id"] == finished.id
    assert reports[0]["session_name"] == "Account creation"
    assert "hidden" not in reports[0]["command"]

    detail = client.get(f"/api/reports/{session.id}/{finished.id}")
    assert detail.status_code == 200, detail.text
    assert "True positive" in detail.json()["markdown"]

    missing = client.get(f"/api/reports/{session.id}/missing")
    assert missing.status_code == 404
