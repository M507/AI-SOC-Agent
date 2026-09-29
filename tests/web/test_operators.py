"""Operators manages the single console account."""

import json

from fastapi.testclient import TestClient

from src.ai_controller.web.auth import _login_failures, _sessions, hash_password, is_password_hash, password_matches
from src.ai_controller.web.server import app, initialize

TEST_PASSWORD = "test-password"


def _client(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "web": {
                    "username": "admin",
                    "password": hash_password(TEST_PASSWORD),
                    "session_secret": "test-session-secret-value-minimum-32-chars-long",
                    "session_ttl_seconds": 43200,
                }
            }
        )
    )
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    _sessions.clear()
    _login_failures.clear()
    initialize(
        config_storage_dir=str(tmp_path / "sessions"),
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    client = TestClient(app, base_url="https://testserver")
    login = client.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    return client, config_path


def test_operator_lists_approval_groups(tmp_path, monkeypatch):
    client, _config = _client(tmp_path, monkeypatch)
    loaded = client.get("/api/operators")
    assert loaded.status_code == 200, loaded.text
    body = loaded.json()
    assert body["username"] == "admin"
    labels = [group["label"] for group in body["groups"]]
    assert labels == ["SOC", "Detection engineering", "Engineering"]
    soc = body["groups"][0]["actions"]
    assert any(item["label"] == "Close alert" for item in soc)
    assert TEST_PASSWORD not in loaded.text


def test_operator_rejects_a_wrong_or_weak_password_and_accepts_a_new_one(tmp_path, monkeypatch):
    client, config_path = _client(tmp_path, monkeypatch)
    wrong = client.post(
        "/api/operators",
        json={
            "current_password": "nope",
            "username": "admin",
            "new_password": "a-new-secret-value",
            "confirm_password": "a-new-secret-value",
        },
    )
    assert wrong.status_code == 400
    assert wrong.json()["errors"]["current_password"]

    weak = client.post(
        "/api/operators",
        json={
            "current_password": TEST_PASSWORD,
            "username": "admin",
            "new_password": "password",
            "confirm_password": "password",
        },
    )
    assert weak.status_code == 400
    assert weak.json()["errors"]["new_password"]
    kept = json.loads(config_path.read_text())["web"]["password"]
    assert is_password_hash(kept)
    assert kept != TEST_PASSWORD
    assert password_matches(TEST_PASSWORD, kept)

    mismatch = client.post(
        "/api/operators",
        json={
            "current_password": TEST_PASSWORD,
            "username": "analyst",
            "new_password": "a-new-secret-value",
            "confirm_password": "different",
        },
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["errors"]["confirm_password"]

    saved = client.post(
        "/api/operators",
        json={
            "current_password": TEST_PASSWORD,
            "username": "analyst",
            "new_password": "a-new-secret-value",
            "confirm_password": "a-new-secret-value",
        },
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["username"] == "analyst"
    still = client.get("/api/operators")
    assert still.status_code == 200
    assert still.json()["username"] == "analyst"

    stored = json.loads(config_path.read_text())["web"]
    assert stored["username"] == "analyst"
    assert is_password_hash(stored["password"])
    assert stored["password"] != "a-new-secret-value"
    assert "a-new-secret-value" not in stored["password"]
    assert password_matches("a-new-secret-value", stored["password"])
    assert stored["session_secret"] == "test-session-secret-value-minimum-32-chars-long"

    fresh = TestClient(app, base_url="https://testserver")
    old = fresh.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert old.status_code == 401
    new = fresh.post("/api/auth/login", json={"username": "analyst", "password": "a-new-secret-value"})
    assert new.status_code == 200
