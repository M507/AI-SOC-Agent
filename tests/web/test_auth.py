"""Web UI authentication: unauthenticated requests must not reach the app."""

from fastapi.testclient import TestClient

from src.ai_controller.web.auth import (
    COOKIE_NAME,
    SessionManagerAuth,
    WebAuthConfig,
    _login_failures,
    _sessions,
)
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod

TEST_PASSWORD = "test-password"


def _client():
    _sessions.clear()
    _login_failures.clear()
    initialize(
        config_storage_dir="data/ai_controller",
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
    return TestClient(app, base_url="https://testserver")


def test_root_redirects_to_login_when_anonymous():
    client = _client()
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login")


def test_api_sessions_rejected_without_session():
    client = _client()
    response = client.get("/api/sessions")
    assert response.status_code == 401


def test_static_rejected_without_session():
    client = _client()
    response = client.get("/static/css/base.css", follow_redirects=False)
    assert response.status_code in (302, 401)


def test_docs_are_disabled():
    client = _client()
    assert client.get("/docs", follow_redirects=False).status_code in (302, 401, 404)
    assert client.get("/openapi.json", follow_redirects=False).status_code in (302, 401, 404)


def test_login_page_is_public():
    client = _client()
    response = client.get("/login")
    assert response.status_code == 200
    assert "Sign in" in response.text
    assert "SOC AI" in response.text


def test_wrong_password_is_rejected():
    client = _client()
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "not-the-password"},
    )
    assert response.status_code == 401
    assert COOKIE_NAME not in response.cookies


def test_login_then_ui_is_reachable():
    client = _client()
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert COOKIE_NAME in client.cookies

    home = client.get("/")
    assert home.status_code == 200
    assert "SOC AI Agents Orchestrator" in home.text

    sessions = client.get("/api/sessions")
    assert sessions.status_code == 200
    assert sessions.json()["success"] is True

    set_cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "samesite=strict" in set_cookie.lower()
    assert "Strict-Transport-Security" in home.headers


def test_logout_revokes_session():
    client = _client()
    client.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200
    blocked = client.get("/api/sessions")
    assert blocked.status_code == 401


def test_http_scheme_is_rejected():
    _sessions.clear()
    _login_failures.clear()
    initialize(
        config_storage_dir="data/ai_controller",
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    client = TestClient(app, base_url="http://testserver")
    assert client.get("/login").status_code == 403
    assert client.get("/").status_code == 403
    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_PASSWORD},
    ).status_code == 403


def test_create_app_honors_debug_env(monkeypatch):
    monkeypatch.setenv("SAMI_DEBUG_UI", "1")
    monkeypatch.setenv("SAMI_MCP_AUTO_START", "0")
    monkeypatch.setenv("SAMI_STORAGE_DIR", "data/ai_controller")
    monkeypatch.setenv("SAMI_COOKIE_SECURE", "1")
    from src.ai_controller.web import server as web_server

    web_server.create_app()
    assert web_server.UI_DEBUG_MODE is True
    assert web_server.MCP_AUTO_START is False


def test_reload_watches_source_and_config():
    from pathlib import Path

    from src.ai_controller.web.server import uvicorn_reload_kwargs

    kwargs = uvicorn_reload_kwargs(Path("/tmp/proj"))
    assert kwargs["reload"] is True
    assert kwargs["reload_dirs"] == [str(Path("/tmp/proj") / "src")]
    assert "config.json" not in kwargs["reload_includes"]
    assert "*.js" in kwargs["reload_includes"]
    assert "logs" in kwargs["reload_excludes"]
    assert "venv" in kwargs["reload_excludes"]
