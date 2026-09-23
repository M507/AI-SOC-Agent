"""Unified integrations settings API."""

import json

from fastapi.testclient import TestClient

from src.ai_controller.web import auth as auth_mod
from src.ai_controller.web.auth import SessionManagerAuth, WebAuthConfig, _login_failures, _sessions
from src.ai_controller.web.server import app, initialize


TEST_PASSWORD = "test-password"


def _client(tmp_path, monkeypatch, elastic=None):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "elastic": elastic or {"clusters": []},
                "thehive": {
                    "base_url": "https://thehive.example.com",
                    "api_key": "your-key",
                },
                "llm": {
                    "provider": "custom",
                    "custom": {
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "local-model",
                    },
                },
                "mcp": {"enabled": True, "host": "127.0.0.1", "port": 8082},
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
    return client


def test_lists_integrations_without_secrets(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        elastic={
            "default_cluster_id": "lab",
            "clusters": [
                {
                    "id": "lab",
                    "name": "Lab Elasticsearch",
                    "base_url": "https://10.0.0.8:9200",
                    "api_key": "secret-elastic-key",
                    "verify_ssl": False,
                }
            ],
        },
    )

    response = client.get("/api/integrations")
    assert response.status_code == 200, response.text
    body = response.json()
    ids = {item["id"] for item in body["integrations"]}
    assert {"thehive", "iris", "elastic:lab", "edr", "cti", "netbox", "engineering", "llm", "mcp"} <= ids
    assert next(item for item in body["integrations"] if item["id"] == "thehive")["configured"] is False
    elastic_card = next(item for item in body["integrations"] if item["id"] == "elastic:lab")
    assert elastic_card["configured"] is True
    assert elastic_card["has_skill_tests"] is True
    assert elastic_card["skill_count"] > 20
    assert "secret-elastic-key" not in response.text


def test_elastic_card_runs_saved_cluster_probe(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        elastic={
            "default_cluster_id": "lab",
            "clusters": [
                {
                    "id": "lab",
                    "name": "Lab Elasticsearch",
                    "base_url": "https://10.0.0.8:9200",
                    "api_key": "secret-elastic-key",
                    "verify_ssl": False,
                }
            ],
        },
    )
    seen = {}

    def fake_probe(cluster):
        seen["id"] = cluster.id
        seen["verify_ssl"] = cluster.verify_ssl
        return {
            "ok": True,
            "kind": "elasticsearch",
            "message": "Reached Elasticsearch.",
            "details": {"status": "yellow"},
        }

    monkeypatch.setattr("src.ai_controller.web.routes_integrations.probe_cluster", fake_probe)
    response = client.post("/api/integrations/elastic%3Alab/test")
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
    assert seen == {"id": "lab", "verify_ssl": False}


def test_unconfigured_integration_test_is_explained(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post("/api/integrations/thehive/test")
    assert response.status_code == 400
    assert "not configured" in response.json()["detail"]


def test_skill_inventory_marks_critical_skills_skipped(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        elastic={
            "default_cluster_id": "lab",
            "clusters": [
                {
                    "id": "lab",
                    "name": "Lab Elasticsearch",
                    "base_url": "https://10.0.0.8:9200",
                    "api_key": "secret-elastic-key",
                    "verify_ssl": False,
                }
            ],
        },
    )
    response = client.get("/api/integrations/elastic%3Alab/skills")
    assert response.status_code == 200, response.text
    skills = {item["id"]: item for item in response.json()["skills"]}
    assert skills["search_security_events"]["mode"] == "read"
    assert skills["close_alert"]["mode"] == "skip"
    assert "destructive" in skills["close_alert"]["skip_reason"].lower()


def test_skill_test_endpoint_returns_per_skill_results(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        elastic={
            "default_cluster_id": "lab",
            "clusters": [
                {
                    "id": "lab",
                    "name": "Lab Elasticsearch",
                    "base_url": "https://10.0.0.8:9200",
                    "api_key": "secret-elastic-key",
                    "verify_ssl": False,
                }
            ],
        },
    )

    async def fake_run(integration_id, selected):
        assert integration_id == "elastic:lab"
        assert selected == ["search_security_events"]
        return {
            "success": True,
            "integration_id": integration_id,
            "counts": {"passed": 1, "failed": 0, "skipped": 0},
            "skills": [
                {
                    "id": "search_security_events",
                    "label": "Search Security Events",
                    "status": "passed",
                    "message": "Dummy skill call completed.",
                    "duration_ms": 5,
                    "cleanup": None,
                }
            ],
        }

    monkeypatch.setattr("src.ai_controller.web.routes_integrations.run_skill_tests", fake_run)
    response = client.post(
        "/api/integrations/elastic%3Alab/skills/test",
        json={"skills": ["search_security_events"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["skills"][0]["status"] == "passed"
