"""NetBox settings API for the web UI."""

import json

from fastapi.testclient import TestClient

from src.ai_controller.web import auth as auth_mod
from src.ai_controller.web.auth import SessionManagerAuth, WebAuthConfig, _login_failures, _sessions
from src.ai_controller.web.server import app, initialize

TEST_PASSWORD = "test-password"


def _client(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "netbox": {
                    "base_url": "http://10.10.10.79:8851",
                    "api_token": "nbt_secret_token_value",
                    "timeout_seconds": 30,
                    "verify_ssl": False,
                },
                "web": {
                    "username": "admin",
                    "password": TEST_PASSWORD,
                    "session_secret": "test-session-secret-value-minimum-32-chars-long",
                },
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
    client.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    return client, config_path


def test_netbox_settings_masks_token(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    response = client.get("/api/netbox/settings")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    assert body["settings"]["base_url"] == "http://10.10.10.79:8851"
    assert "nbt_secret_token_value" not in response.text
    assert "..." in body["settings"]["api_token"] or "••" in body["settings"]["api_token"]


def test_netbox_settings_save_keeps_masked_token(tmp_path, monkeypatch):
    client, config_path = _client(tmp_path, monkeypatch)
    current = client.get("/api/netbox/settings").json()["settings"]
    response = client.put(
        "/api/netbox/settings",
        json={
            "base_url": "http://10.10.10.79:8851",
            "api_token": current["api_token"],
            "timeout_seconds": 45,
            "verify_ssl": False,
        },
    )
    assert response.status_code == 200, response.text
    on_disk = json.loads(config_path.read_text())
    assert on_disk["netbox"]["api_token"] == "nbt_secret_token_value"
    assert on_disk["netbox"]["timeout_seconds"] == 45


def test_netbox_test_uses_saved_settings(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)

    class FakeClient:
        def ping(self):
            return True

        @classmethod
        def from_config(cls, config):
            assert config.netbox.base_url == "http://10.10.10.79:8851"
            return cls()

    monkeypatch.setattr(
        "src.ai_controller.web.routes_netbox.NetBoxAPIClient",
        FakeClient,
    )
    response = client.post(
        "/api/netbox/test",
        json={
            "base_url": "http://10.10.10.79:8851",
            "api_token": "",
            "timeout_seconds": 30,
            "verify_ssl": False,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
