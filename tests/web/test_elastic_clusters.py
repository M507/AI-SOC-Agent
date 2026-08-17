"""Elastic cluster settings API."""

import json

from fastapi.testclient import TestClient

from src.ai_controller.web.auth import SessionManagerAuth, WebAuthConfig, _login_failures, _sessions
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod

TEST_PASSWORD = "test-password"


def _authed_client(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "elastic": {"clusters": []},
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


def test_create_session_stores_cluster_id(tmp_path, monkeypatch):
    client, _config_path = _authed_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/elastic/clusters",
        json={
            "name": "Lab",
            "base_url": "https://elastic.example:9200",
            "api_key": "encoded-test-api-key",
            "verify_ssl": False,
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["success"] is True
    assert len(body["clusters"]) == 1
    cluster_id = body["clusters"][0]["id"]
    assert "encoded-test-api-key" not in json.dumps(body)

    session = client.post(
        "/api/sessions",
        json={"name": "Investigate lab", "cluster_id": cluster_id},
    )
    assert session.status_code == 200, session.text
    payload = session.json()["session"]
    assert payload["cluster_id"] == cluster_id
    assert payload["cluster"]["name"] == "Lab"
    assert payload["cluster"]["base_url"] == "https://elastic.example:9200"


def test_new_cluster_inherits_default_skill_vector(tmp_path, monkeypatch):
    client, config_path = _authed_client(tmp_path, monkeypatch)
    listed = client.get("/api/elastic/clusters")
    assert listed.status_code == 200, listed.text
    catalog = listed.json()
    assert catalog["skill_catalog"]["prefix"] == "MSV:1"
    group_names = [group["name"] for group in catalog["skill_catalog"]["groups"]]
    assert "IRIS skills" in group_names
    assert "Elastic / ELK skills" in group_names
    elk = next(group for group in catalog["skill_catalog"]["groups"] if group["id"] == "SIEM")
    assert any(skill["id"] == "get_recent_alerts" for skill in elk["skills"])
    assert any(skill["id"] == "search_security_events" for skill in elk["skills"])
    default_vector = catalog["default_skill_vector"]
    assert default_vector.startswith("MSV:1/")

    disabled = client.put(
        "/api/elastic/default-skills",
        json={"skill_vector": "MSV:1/IRIS:N/TH:N/SIEM:Y/EDR:N/CTI:Y/KB:Y/ENG:N/RB:Y/AG:Y/RU:Y"},
    )
    assert disabled.status_code == 200, disabled.text
    default_after = disabled.json()["default_skill_vector"]
    assert "IRIS:N" in default_after
    assert "SIEM:Y" in default_after

    created = client.post(
        "/api/elastic/clusters",
        json={
            "name": "Customer A",
            "base_url": "https://elastic.example:9200",
            "api_key": "encoded-test-api-key",
            "verify_ssl": False,
        },
    )
    assert created.status_code == 200, created.text
    cluster = created.json()["clusters"][0]
    assert cluster["skill_vector"] == default_after

    updated = client.put(
        f"/api/elastic/clusters/{cluster['id']}/skills",
        json={"skill_vector": default_after + "/SK:create_case=Y"},
    )
    assert updated.status_code == 200, updated.text
    saved = updated.json()["clusters"][0]["skill_vector"]
    assert "SK:create_case=Y" in saved
    on_disk = json.loads(config_path.read_text())
    assert on_disk["elastic"]["clusters"][0]["skill_vector"] == saved
    assert on_disk["elastic"]["default_skill_vector"] == default_after


def test_invalid_skill_vector_rejected(tmp_path, monkeypatch):
    client, _config_path = _authed_client(tmp_path, monkeypatch)
    response = client.put(
        "/api/elastic/default-skills",
        json={"skill_vector": "MSV:1/NOT_A_SOLUTION:Y"},
    )
    assert response.status_code == 400


def test_test_cluster_keeps_saved_verify_ssl(tmp_path, monkeypatch):
    client, _config_path = _authed_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/elastic/clusters",
        json={
            "name": "Lab ES",
            "base_url": "https://elastic.example:9200",
            "api_key": "encoded-test-api-key",
            "verify_ssl": False,
        },
    )
    assert created.status_code == 200, created.text
    cluster_id = created.json()["clusters"][0]["id"]
    probed = {}

    def fake_probe(cluster):
        probed["verify_ssl"] = cluster.verify_ssl
        probed["base_url"] = cluster.base_url
        return {
            "ok": True,
            "kind": "elasticsearch",
            "message": f"Reached Elasticsearch at {cluster.base_url}.",
            "details": {"kind": "elasticsearch"},
        }

    monkeypatch.setattr("src.ai_controller.web.routes_elastic.probe_cluster", fake_probe)
    response = client.post(
        "/api/elastic/test",
        json={"id": cluster_id, "base_url": "https://elastic.example:9200"},
    )
    assert response.status_code == 200, response.text
    assert probed["verify_ssl"] is False
    assert response.json()["ok"] is True
