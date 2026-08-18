"""Requests view API and UI shell."""

from pathlib import Path

from fastapi.testclient import TestClient

from src.ai_controller.web.auth import COOKIE_NAME, SessionManagerAuth, WebAuthConfig, _login_failures, _sessions
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod

WEB = Path(__file__).resolve().parents[2] / "src" / "ai_controller" / "web"
INDEX = WEB / "templates" / "index.html"
APP_JS = WEB / "static" / "app.js"
TEST_PASSWORD = "test-password"


def test_requests_view_is_in_the_shell():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    assert 'id="nav-requests"' in html
    assert 'id="requests-content"' in html
    assert "requests.js" in html
    assert "requests.css" in html
    assert "setActiveSection('requests')" in app_js
    assert "RequestsManager" in app_js


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
            password=TEST_PASSWORD,
            session_secret="test-session-secret-value-minimum-32-chars-long",
            session_ttl_seconds=43200,
            cookie_secure=True,
        )
    )
    client = TestClient(app, base_url="https://testserver")
    login = client.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert login.status_code == 200
    assert COOKIE_NAME in client.cookies
    return client


def test_requests_api_create_list_deny(tmp_path):
    client = _client(tmp_path)
    catalog = client.get("/api/requests/catalog")
    assert catalog.status_code == 200
    types = {item["action_type"] for item in catalog.json()["actions"]}
    assert "close_alert" in types
    assert "identity_verify" in types
    assert "update_verdict" not in types

    created = client.post(
        "/api/requests",
        json={
            "action_type": "isolate_endpoint",
            "title": "Isolate WS-1",
            "summary": "Ransomware note found.",
            "payload": {"endpoint_id": "host-1"},
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request"]["id"]

    listed = client.get("/api/requests?status=pending")
    assert listed.status_code == 200
    assert listed.json()["counts"]["pending"] >= 1
    assert any(item["id"] == request_id for item in listed.json()["requests"])

    denied = client.post(f"/api/requests/{request_id}/deny", json={"comment": "need more evidence"})
    assert denied.status_code == 200
    assert denied.json()["request"]["status"] == "denied"
