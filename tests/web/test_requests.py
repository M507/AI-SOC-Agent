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
    assert 'data-request-refresh' in html
    assert 'requests-refresh-btn' in html
    assert 'data-request-filter="archived"' in html
    assert 'data-request-filter="open"' in html
    assert 'data-request-queue="all"' in html
    assert 'data-request-queue="soc"' in html
    assert 'data-request-queue="engineering"' in html
    assert 'data-request-queue="detection"' in html
    assert "Approval queue (ALL)" in html
    assert "Detection engineering" in html
    assert "requests.js" in html
    assert "requests.css" in html
    assert "setActiveSection('requests')" in app_js
    assert "RequestsManager" in app_js
    assert "setQueueTab" in app_js
    assert "request-decision-bar" in requests_js
    assert "bulk-approve" in requests_js
    assert "bulk-ignore" in requests_js
    assert "handleBulk" in requests_js
    assert "handleAction" in requests_js
    assert "_inFlight" in requests_js
    assert "settleLocally" in requests_js
    assert "this.handleAction(action)" in requests_js
    assert "await this.handleAction(action)" not in requests_js
    assert "refreshFromTickets" in requests_js
    assert "archived" in requests_js
    assert "Waiting on integration" in requests_js
    assert 'data-request-action="ignore"' in requests_js
    assert 'data-request-action="approve"' in requests_js
    assert "Needs approval" in requests_js
    assert "Proposed note" in requests_js
    assert "Associated notes (approved with this close)" in requests_js
    assert "Approve will also write" in requests_js
    assert "request-bulk-comment" in requests_js
    assert "Technical details" in requests_js
    assert "matchesQueue" in requests_js
    assert "startLocalPoll" in requests_js
    assert "justOpened" in app_js
    assert "getRequestsSummary" in (WEB / "static" / "api.js").read_text(encoding="utf-8")


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


def test_requests_sync_reports_linked_tickets(tmp_path):
    client = _client(tmp_path)
    synced = client.post("/api/requests/sync")
    assert synced.status_code == 200, synced.text
    body = synced.json()
    assert body["success"] is True
    assert body["checked"] == 0
    assert body["closed"] == 0
    assert "No linked tickets" in body["message"]


def test_requests_api_create_list_deny(tmp_path):
    client = _client(tmp_path)
    catalog = client.get("/api/requests/catalog")
    assert catalog.status_code == 200
    types = {item["action_type"] for item in catalog.json()["actions"]}
    assert "close_alert" in types
    assert "add_alert_note" in types
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
    soc = client.get("/api/requests?status=open&queue=soc")
    assert soc.status_code == 200
    assert all(item["id"] != request_id for item in soc.json()["requests"])
    detection = client.get("/api/requests?status=open&queue=detection")
    assert detection.status_code == 200
    assert any(item["id"] == request_id for item in detection.json()["requests"])
    assert "actionable" in listed.json()["counts"]
    assert "tab_counts" in detection.json()
    js = Path(__file__).resolve().parents[2] / "src" / "ai_controller" / "web" / "static" / "requests.js"
    text = js.read_text(encoding="utf-8")
    assert "isInformational" in text
    assert "Informational only" in text
    assert 'data-request-action="approve"' in text
    assert "queueTab" in text
    assert 'data-request-action="ignore"' in text
    assert 'data-request-action="create-runbook"' in text
    assert "Create runbook" in text
    assert "canCreateRunbook" in text


def test_create_runbook_starts_session_and_marks_done(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMI_RUNBOOKS_DIR", str(tmp_path / "run_books"))
    (tmp_path / "run_books" / "soc1" / "cases").mkdir(parents=True)

    client = _client(tmp_path)
    created = client.post(
        "/api/requests",
        json={
            "action_type": "runbook_gap",
            "title": "Need case runbook: Impossible Travel",
            "summary": "No case playbook matched",
            "rationale": "Generic triage only",
            "payload": {
                "title": "Need case runbook: Impossible Travel",
                "description": "Need GeoIP + VPN checks for impossible travel.",
                "rule_name": "Impossible Travel",
                "alert_type": "impossible travel",
                "alert_id": "alert-travel-1",
                "suggested_path": "soc1/cases/impossible_travel_triage",
                "alert": {
                    "id": "alert-travel-1",
                    "title": "Impossible Travel",
                    "severity": "medium",
                },
                "investigation_summary": "BTP after VPN confirmation",
            },
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()["request"]
    assert body["status"] == "informational"
    request_id = body["id"]

    started = client.post(f"/api/requests/{request_id}/create-runbook", json={"comment": "author it"})
    assert started.status_code == 200, started.text
    payload = started.json()
    assert payload["success"] is True
    assert payload["target_path"] == "soc1/cases/impossible_travel_triage"
    assert payload["session"]["id"]
    assert payload["request"]["status"] == "acknowledged"
    assert payload["request"]["execution_result"]["create_runbook"]["session_id"] == payload["session"]["id"]

    wrong = client.post(
        f"/api/requests/{request_id}/create-runbook",
        json={},
    )
    assert wrong.status_code == 400

    close_created = client.post(
        "/api/requests",
        json={
            "action_type": "close_alert",
            "title": "Close something",
            "summary": "fp",
            "payload": {"alert_id": "a1", "reason": "false_positive", "comment": "noise"},
        },
    )
    assert close_created.status_code == 200
    reject = client.post(
        f"/api/requests/{close_created.json()['request']['id']}/create-runbook",
        json={},
    )
    assert reject.status_code == 400


def test_ignore_archives_informational_request(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue.lab_rules import clear_index_cache

    monkeypatch.setenv("SAMI_LAB_RULES_DIR", str(tmp_path / "empty-rules"))
    clear_index_cache()
    client = _client(tmp_path)
    created = client.post(
        "/api/requests",
        json={
            "action_type": "visibility",
            "title": "Missing DNS telemetry",
            "summary": "No DNS logs",
            "payload": {"title": "Missing DNS telemetry", "description": "Need DNS logs"},
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request"]["id"]
    ignored = client.post(f"/api/requests/{request_id}/ignore", json={"comment": "out of scope"})
    assert ignored.status_code == 200, ignored.text
    body = ignored.json()["request"]
    assert body["status"] == "acknowledged"
    assert body["archived"] is True
    assert body["decision"]["action"] == "ignore"
    open_list = client.get("/api/requests?status=open&queue=detection")
    assert all(item["id"] != request_id for item in open_list.json()["requests"])
    archived = client.get("/api/requests?status=archived&queue=detection")
    assert any(item["id"] == request_id for item in archived.json()["requests"])


def test_add_alert_note_request_approve_writes_and_deny_does_not(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue.clients import ClientBundle

    class _FakeSIEM:
        def __init__(self):
            self.notes = []

        def get_security_alert_by_id(self, alert_id, include_detections=True):
            return {"id": alert_id, "title": "User Account Creation"}

        def add_alert_note(self, alert_id, note):
            self.notes.append((alert_id, note))
            return {"alert_id": alert_id, "note": note, "alert": {}}

    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id="lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)

    client = _client(tmp_path)
    created = client.post(
        "/api/requests",
        json={
            "action_type": "add_alert_note",
            "title": "Add note: User Account Creation",
            "summary": "Proposed investigation note for review.",
            "payload": {
                "alert_id": "alert-ui-1",
                "note": "Proposed investigation note for review.",
            },
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()["request"]
    assert body["status"] == "pending"
    assert body["action_type"] == "add_alert_note"
    assert body["payload"]["note"] == "Proposed investigation note for review."
    assert siem.notes == []

    approved = client.post(f"/api/requests/{body['id']}/approve", json={})
    assert approved.status_code == 200, approved.text
    assert approved.json()["request"]["status"] == "executed"
    assert siem.notes == [("alert-ui-1", "Proposed investigation note for review.")]

    second = client.post(
        "/api/requests",
        json={
            "action_type": "add_alert_note",
            "title": "Add note: denied",
            "summary": "This note must not be written.",
            "payload": {"alert_id": "alert-ui-2", "note": "This note must not be written."},
        },
    )
    assert second.status_code == 200, second.text
    denied = client.post(
        f"/api/requests/{second.json()['request']['id']}/deny",
        json={"comment": "not yet"},
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["request"]["status"] == "denied"
    assert siem.notes == [("alert-ui-1", "Proposed investigation note for review.")]


def test_list_defaults_to_summary_cards(tmp_path):
    client = _client(tmp_path)
    created = client.post(
        "/api/requests",
        json={
            "action_type": "close_alert",
            "title": "Close noisy DNS",
            "summary": "scanner",
            "payload": {"alert_id": "alert-summary-1", "reason": "false_positive", "comment": "noise"},
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request"]["id"]
    assert "payload" in created.json()["request"]

    listed = client.get("/api/requests?status=open")
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["success"] is True
    assert "generation" in body
    assert "queue_counts" in body
    assert "soc" in body["queue_counts"]
    match = next(item for item in body["requests"] if item["id"] == request_id)
    assert "payload" not in match
    assert match["alert_id"] == "alert-summary-1"
    assert match["action_type"] == "close_alert"
    assert match["category"] == "siem"

    summary = client.get("/api/requests/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["success"] is True
    assert summary.json()["generation"] == body["generation"]
    assert "actionable" in summary.json()["counts"]

    full = client.get(f"/api/requests/{request_id}")
    assert full.status_code == 200, full.text
    assert full.json()["request"]["payload"]["alert_id"] == "alert-summary-1"

    full_list = client.get("/api/requests?status=open&view=full")
    assert full_list.status_code == 200
    full_match = next(item for item in full_list.json()["requests"] if item["id"] == request_id)
    assert full_match["payload"]["alert_id"] == "alert-summary-1"
