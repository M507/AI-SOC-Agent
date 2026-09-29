"""Read-only library stays inside the markdown trees."""

from fastapi.testclient import TestClient

from src.ai_controller.web.auth import COOKIE_NAME, SessionManagerAuth, WebAuthConfig, _login_failures, _sessions, hash_password
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod


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


def test_library_lists_role_groups_and_reads_a_document(tmp_path):
    client = _client(tmp_path)
    listed = client.get("/api/library/runbooks")
    assert listed.status_code == 200, listed.text
    groups = {group["id"]: group for group in listed.json()["groups"]}
    assert "soc1" in groups
    assert groups["soc1"]["files"]

    doc = client.get("/api/library/documentation/file", params={"path": "requests.md"})
    assert doc.status_code == 200, doc.text
    body = doc.json()
    assert body["success"] is True
    assert "Requests" in body["markdown"]


def test_library_rejects_paths_outside_the_folder(tmp_path):
    client = _client(tmp_path)
    escaped = client.get("/api/library/documentation/file", params={"path": "../config.json"})
    assert escaped.status_code == 400
    absolute = client.get("/api/library/standards/file", params={"path": "/etc/passwd"})
    assert absolute.status_code == 400
    python = client.get(
        "/api/library/runbooks/file",
        params={"path": "soc1/triage/flow_initial_alert_triage.py"},
    )
    assert python.status_code == 400
    unknown = client.get("/api/library/secrets")
    assert unknown.status_code == 404
