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
    requests_js = (WEB / "static" / "requests.js").read_text(encoding="utf-8")
    assert 'id="nav-requests"' in html
    assert 'id="requests-content"' in html
    assert 'id="requests-bulk-bar"' in html
    assert 'data-request-select-all' in html
    assert 'data-request-filter="archived"' in html
    assert 'data-request-filter="open"' in html
    assert "requests.js" in html
    assert "requests.css" in html
    assert "setActiveSection('requests')" in app_js
    assert "RequestsManager" in app_js
    assert "request-decision-bar" in requests_js
    assert "bulk-approve" in requests_js
    assert "handleBulk" in requests_js
    assert "archived" in requests_js


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


def test_requests_bulk_deny(tmp_path):
    client = _client(tmp_path)
    ids = []
    for index in range(2):
        created = client.post(
            "/api/requests",
            json={
                "action_type": "close_alert",
                "title": f"Close alert {index}",
                "summary": "noise",
                "payload": {"alert_id": f"alert-bulk-{index}", "reason": "false_positive", "comment": "scanner"},
            },
        )
        assert created.status_code == 200, created.text
        ids.append(created.json()["request"]["id"])

    bulk = client.post(
        "/api/requests/bulk",
        json={"action": "deny", "request_ids": ids, "comment": "batch cleanup"},
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["success"] is True
    assert body["succeeded"] == 2
    assert body["failed"] == 0
    for request_id in ids:
        detail = client.get(f"/api/requests/{request_id}")
        assert detail.status_code == 200
        assert detail.json()["request"]["status"] == "denied"


def test_informational_can_be_marked_done(tmp_path, monkeypatch):
    import json
    from pathlib import Path

    from src.ai_controller.approval_queue.lab_rules import clear_index_cache

    rules = tmp_path / "lab-rules"
    rules.mkdir()
    (rules / "[enabled]_Suspicious_PowerShell_Encoded_Command_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.json").write_text(
        json.dumps(
            {
                "_dac": {
                    "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "elastic_id": "elastic-aaaa",
                    "name": "Suspicious PowerShell Encoded Command",
                },
                "rule": {
                    "name": "Suspicious PowerShell Encoded Command",
                    "description": "Detects encoded PowerShell",
                    "query": "process.name:powershell.exe",
                    "language": "kuery",
                    "tags": ["Windows"],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(rules))
    clear_index_cache()

    client = _client(tmp_path)
    created = client.post(
        "/api/requests",
        json={
            "action_type": "fine_tune",
            "title": "Tune encoded PS rule",
            "summary": "Benign admin script",
            "payload": {
                "title": "Tune encoded PS rule",
                "description": "Exclude signed admin tool",
                "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "suggestion": "Exclude signed admin tool",
            },
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request"]["id"]
    assert created.json()["request"]["status"] == "informational"

    done = client.post(f"/api/requests/{request_id}/acknowledge", json={"comment": "reviewed"})
    assert done.status_code == 200, done.text
    assert done.json()["request"]["status"] == "acknowledged"
    assert done.json()["request"]["archived"] is True

    open_list = client.get("/api/requests?status=open")
    assert open_list.status_code == 200
    assert all(item["id"] != request_id for item in open_list.json()["requests"])

    archived = client.get("/api/requests?status=archived")
    assert archived.status_code == 200
    assert any(item["id"] == request_id for item in archived.json()["requests"])
    assert archived.json()["counts"]["archived"] >= 1


def test_fine_tune_api_is_informational(tmp_path, monkeypatch):
    import json
    from pathlib import Path

    from src.ai_controller.approval_queue.lab_rules import clear_index_cache

    rules = tmp_path / "lab-rules"
    rules.mkdir()
    (rules / "[enabled]_Suspicious_PowerShell_Encoded_Command_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.json").write_text(
        json.dumps(
            {
                "_dac": {
                    "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "elastic_id": "elastic-aaaa",
                    "name": "Suspicious PowerShell Encoded Command",
                },
                "rule": {
                    "name": "Suspicious PowerShell Encoded Command",
                    "description": "Detects encoded PowerShell.",
                    "query": "process.name: powershell.exe and process.args: *-enc*",
                    "language": "kuery",
                    "index": ["logs-endpoint.events.process-*"],
                    "tags": ["Data Source: Elastic Endgame"],
                    "enabled": True,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(rules))
    clear_index_cache()
    client = _client(tmp_path / "web")
    created = client.post(
        "/api/requests",
        json={
            "action_type": "fine_tune",
            "title": "Tune encoded PowerShell",
            "summary": "Lab admin FPs.",
            "payload": {
                "title": "Tune encoded PowerShell",
                "description": "Exclude the signed build-server user.",
                "rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            },
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()["request"]
    assert body["status"] == "informational"
    assert body["payload"]["rule_found"] is True
    assert "powershell.exe" in body["payload"]["rule"]["query"]
    request_id = body["id"]
    approve = client.post(f"/api/requests/{request_id}/approve", json={})
    assert approve.status_code == 400
    listed = client.get("/api/requests?status=pending")
    assert any(item["id"] == request_id for item in listed.json()["requests"])
    js = Path(__file__).resolve().parents[2] / "src" / "ai_controller" / "web" / "static" / "requests.js"
    text = js.read_text(encoding="utf-8")
    assert "isInformational" in text
    assert "Informational only" in text
    assert "data-request-action=\"approve\"" in text
