"""Detection as Code shell and rules search."""

from pathlib import Path

import json

from fastapi.testclient import TestClient

from src.ai_controller.approval_queue.lab_rules import clear_index_cache
from src.ai_controller.web.auth import COOKIE_NAME, SessionManagerAuth, WebAuthConfig, _login_failures, _sessions, hash_password
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod

WEB = Path(__file__).resolve().parents[2] / "src" / "ai_controller" / "web"
INDEX = WEB / "templates" / "index.html"
APP_JS = WEB / "static" / "app.js"
TEST_PASSWORD = "test-password"


def test_detection_section_is_in_the_shell():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    detections_js = (WEB / "static" / "detections.js").read_text(encoding="utf-8")
    assert 'id="nav-findings"' in html
    assert 'id="nav-rules"' in html
    assert 'id="nav-detection-review"' in html
    assert 'id="detections-content"' in html
    assert 'id="findings-search"' in html
    assert 'id="rules-search"' in html
    assert 'id="review-conditions"' in html
    assert 'id="review-diff"' in html
    assert "Ask about this finding" in html
    assert "Create exception from checked fields" in html
    assert "detections.js" in html
    assert "detections.css" in html
    assert "'detections'" in app_js
    assert "DetectionsManager" in detections_js
    assert 'id="detection-rules-dir"' in html
    assert 'id="detection-findings-hours"' in html
    assert 'id="detection-match-hours"' in html
    assert "saveDetectionSettings" in app_js


def _client(tmp_path, monkeypatch, rules):
    _sessions.clear()
    _login_failures.clear()
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(rules))
    clear_index_cache()
    initialize(
        config_storage_dir=str(tmp_path),
        debug_ui=False,
        mcp_auto_start=False,
        cookie_secure=True,
    )
    auth_mod._auth = SessionManagerAuth(
        WebAuthConfig(
            username="admin",
            password=hash_password(TEST_PASSWORD),
            session_secret="test-session-secret-value-minimum-32-chars-long",
            session_ttl_seconds=43200,
            cookie_secure=True,
        )
    )
    client = TestClient(app, base_url="https://testserver")
    signed = client.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert signed.status_code == 200
    assert COOKIE_NAME in client.cookies
    return client


def test_rules_search_reads_the_configured_folder(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    rule_id = "210d9ca8-5508-47aa-991a-05e8fa386cc7"
    (rules / f"[enabled]_country_{rule_id}.json").write_text(
        '{"_dac":{"rule_id":"%s","status":"enabled"},"rule":{"name":"Country Check","rule_id":"%s","severity":"low","language":"kuery","query":"ntopng.script:country_check","enabled":true}}' % (rule_id, rule_id),
        encoding="utf-8",
    )
    client = _client(tmp_path, monkeypatch, rules)
    found = client.get("/api/detections/rules", params={"q": "country", "limit": 50})
    assert found.status_code == 200
    body = found.json()
    assert body["configured"] is True
    assert body["rules"][0]["name"] == "Country Check"
    detail = client.get(f"/api/detections/rules/{rule_id}")
    assert detail.status_code == 200
    assert "country_check" in detail.json()["rule"]["query"]


def test_detection_settings_save_the_rules_folder(tmp_path, monkeypatch):
    rules = tmp_path / "saved-rules"
    rules.mkdir()
    monkeypatch.delenv("SAMI_LAB_RULES_DIR", raising=False)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({
            "web": {
                "username": "admin",
                "password": hash_password(TEST_PASSWORD),
                "session_secret": "test-session-secret-value-minimum-32-chars-long",
            }
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    client = _client(tmp_path, monkeypatch, rules)
    saved = client.put(
        "/api/detections/settings",
        json={"rules_dir": str(rules), "findings_hours": 48, "match_hours": 72},
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()["settings"]
    assert body["rules_dir"] == str(rules.resolve())
    assert body["configured"] is True
    assert body["findings_hours"] == 48
    assert body["match_hours"] == 72
    monkeypatch.delenv("SAMI_LAB_RULES_DIR", raising=False)
    again = client.get("/api/detections/settings")
    assert again.json()["settings"]["effective_path"] == str(rules.resolve())
    assert again.json()["settings"]["env_override"] is False
    missing = client.put("/api/detections/settings", json={"rules_dir": str(tmp_path / "missing-folder")})
    assert missing.status_code == 400
