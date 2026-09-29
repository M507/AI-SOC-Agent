"""Setup wizard: fresh boot, golden-path mapping, and placeholder skips."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.ai_controller.web import auth as auth_mod
from src.ai_controller.web.auth import (
    _login_failures,
    _sessions,
    hash_password,
    setup_required,
)
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web.setup_wizard import cluster_flags, derive_cluster_vector
from src.mcp.factory import config_file_path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = json.loads((ROOT / "config.json.example").read_text(encoding="utf-8"))
PASSWORD = "onboarding-test-password"
CLUSTER_VECTOR = "MSV:1/IRIS:N/TH:N/SIEM:Y/EDR:N/CTI:Y/KB:N/NB:Y/ENG:Y/RB:Y/AG:N/RU:Y"
DEFAULT_VECTOR = "MSV:1/IRIS:Y/TH:N/SIEM:Y/EDR:N/CTI:Y/KB:Y/NB:Y/ENG:N/RB:Y/AG:N/RU:Y"


def _fresh_client(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    monkeypatch.setattr("src.core.config_storage.STARTING_CONFIG_FILE", str(ROOT / "config.json.example"))
    _sessions.clear()
    _login_failures.clear()
    auth_mod._auth = None
    initialize(
        config_storage_dir=str(tmp_path / "sessions"),
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    return TestClient(app, base_url="https://testserver"), config_path


def _signed_in_client(tmp_path, monkeypatch):
    config = json.loads(json.dumps(EXAMPLE))
    config["web"]["password"] = hash_password(PASSWORD)
    config["web"]["session_secret"] = "test-session-secret-value-minimum-32-chars-long"
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    monkeypatch.setattr("src.core.config_storage.STARTING_CONFIG_FILE", str(ROOT / "config.json.example"))
    _sessions.clear()
    _login_failures.clear()
    auth_mod._auth = None
    initialize(
        config_storage_dir=str(tmp_path / "sessions"),
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    return TestClient(app, base_url="https://testserver"), config_path


def test_fresh_install_opens_setup(tmp_path, monkeypatch):
    client, _ = _fresh_client(tmp_path, monkeypatch)
    assert setup_required() is True
    home = client.get("/", follow_redirects=False)
    assert home.status_code == 302
    assert home.headers["location"] == "/setup"
    status = client.get("/api/setup/status")
    assert status.status_code == 200
    assert status.json()["setup_required"] is True
    page = client.get("/setup")
    assert page.status_code == 200
    assert "Skip for now" in page.text
    schema = client.get("/api/setup/schema")
    assert schema.status_code == 200
    ids = [step["id"] for step in schema.json()["steps"]]
    assert ids[0] == "welcome"
    assert "security" in ids and "siem" in ids and "ai" in ids


def test_existing_password_is_not_gated(tmp_path, monkeypatch):
    client, _ = _signed_in_client(tmp_path, monkeypatch)
    assert setup_required() is False
    home = client.get("/", follow_redirects=False)
    assert home.status_code == 302
    assert home.headers["location"].startswith("/login")
    blocked = client.get("/api/setup/status")
    assert blocked.status_code == 401


def test_cluster_vector_matches_golden_choices():
    choices = {
        "siem": "elastic",
        "case": "skip",
        "edr": "skip",
        "cti": "local_tip",
        "opencti": False,
        "kb": False,
        "netbox": True,
        "eng": "github",
    }
    assert cluster_flags(choices)["EDR"] is False
    assert cluster_flags(choices)["IRIS"] is False
    assert derive_cluster_vector(choices) == CLUSTER_VECTOR


def test_wizard_reaches_configured_sections(tmp_path, monkeypatch):
    client, config_path = _fresh_client(tmp_path, monkeypatch)
    assert client.post("/api/setup/steps/welcome", json={"action": "next", "values": {}}).status_code == 200

    security = client.post(
        "/api/setup/steps/security",
        json={
            "action": "save",
            "values": {
                "username": "admin",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
                "session_ttl_seconds": 43200,
            },
        },
    )
    assert security.status_code == 200, security.text

    siem = client.post(
        "/api/setup/steps/siem",
        json={
            "action": "save",
            "values": {
                "id": "lab-88-es",
                "name": "Lab Elasticsearch",
                "base_url": "https://10.10.10.88:9200",
                "api_key": "elastic-test-api-key",
                "kibana_url": "",
            },
        },
    )
    assert siem.status_code == 200, siem.text
    assert client.post("/api/setup/steps/cases", json={"action": "skip", "values": {}}).status_code == 200
    assert client.post("/api/setup/steps/edr", json={"action": "skip", "values": {}}).status_code == 200
    cti = client.post(
        "/api/setup/steps/cti",
        json={"action": "save", "values": {"base_url": "http://10.10.10.95:8084", "use_opencti": False}},
    )
    assert cti.status_code == 200, cti.text
    knowledge = client.post(
        "/api/setup/steps/knowledge",
        json={
            "action": "save",
            "values": {
                "kb": False,
                "base_url": "http://10.10.10.79:8851",
                "api_token": "netbox-test-token",
            },
        },
    )
    assert knowledge.status_code == 200, knowledge.text
    eng = client.post(
        "/api/setup/steps/eng",
        json={
            "action": "save",
            "values": {
                "provider": "github",
                "api_token": "github-test-token",
                "repository": "M507/HomeLab-DaC",
                "fine_tuning_label": "fine-tuning",
                "visibility_label": "visibility",
            },
        },
    )
    assert eng.status_code == 200, eng.text
    ai = client.post(
        "/api/setup/steps/ai",
        json={
            "action": "save",
            "values": {
                "provider": "openwebui",
                "base_url": "http://10.10.10.82:8080",
                "api_key": "openwebui-test-token",
                "model": "auto",
                "enabled": True,
                "auto_start": True,
                "port": 8082,
                "tls": False,
                "public_url": "http://10.10.10.33:8082/mcp",
                "mcp_api_token": "mcp-test-token",
                "default_skill_vector": DEFAULT_VECTOR,
            },
        },
    )
    assert ai.status_code == 200, ai.text
    done = client.post("/api/setup/complete")
    assert done.status_code == 200, done.text

    saved = json.loads(config_path.read_text(encoding="utf-8"))
    cluster = saved["elastic"]["clusters"][0]
    assert cluster["id"] == "lab-88-es"
    assert cluster["verify_ssl"] is False
    assert cluster["kibana_url"] == ""
    assert cluster["api_key"] == "elastic-test-api-key"
    assert cluster["skill_vector"] == CLUSTER_VECTOR
    assert saved["elastic"]["default_skill_vector"] == DEFAULT_VECTOR
    assert saved["elastic"]["base_url"] == "https://10.10.10.88:9200"
    assert saved["elastic"]["verify_ssl"] is False
    assert saved["cti"]["base_url"] == "http://10.10.10.95:8084"
    assert saved["cti"]["verify_ssl"] is False
    assert saved["netbox"]["api_token"] == "netbox-test-token"
    assert saved["netbox"]["verify_ssl"] is False
    assert saved["mcp"]["host"] == "0.0.0.0"
    assert saved["mcp"]["tls"] is False
    assert saved["mcp"]["api_token"] == "mcp-test-token"
    assert saved["llm"]["provider"] == "openwebui"
    assert saved["llm"]["openwebui"]["model"] == "auto"
    assert saved["llm"]["openwebui"]["mcp_server_id"] == "samigpt-mcp"
    assert saved["eng"]["provider"] == "github"
    assert saved["eng"]["github"]["repository"] == "M507/HomeLab-DaC"
    assert saved["eng"]["trello"] == EXAMPLE["eng"]["trello"]
    assert saved["eng"]["clickup"] == EXAMPLE["eng"]["clickup"]
    assert saved["edr"] == EXAMPLE["edr"]
    assert saved["iris"] == EXAMPLE["iris"]
    assert saved["thehive"] == EXAMPLE["thehive"]
    assert saved["cti_opencti"] == EXAMPLE["cti_opencti"]
    assert saved["web"]["username"] == "admin"
    assert saved["web"]["password"].startswith("$argon2id$")
    assert saved["web"]["password"] != PASSWORD
    assert len(saved["web"]["session_secret"]) >= 32
    assert saved["setup"]["completed"] is True
    schema = client.get("/api/setup/schema")
    assert "elastic-test-api-key" not in schema.text
    assert "github-test-token" not in schema.text


def test_mcp_config_path_follows_env(monkeypatch, tmp_path):
    target = tmp_path / "isolated.json"
    monkeypatch.setenv("SAMIGPT_CONFIG_FILE", str(target))
    assert config_file_path() == target
