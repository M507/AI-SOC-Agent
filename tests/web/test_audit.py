"""Audit merges sign-ins, chats, and approval decisions."""

from fastapi.testclient import TestClient

from src.ai_controller.approval_queue import get_queue
from src.ai_controller.approval_queue.models import ApprovalRequest, Decision, RequestStatus
from src.ai_controller.web import auth as auth_mod
from src.ai_controller.web.audit_log import audit_log_path
from src.ai_controller.web.auth import SessionManagerAuth, WebAuthConfig, _login_failures, _sessions, hash_password
from src.ai_controller.web import server as web_server
from src.ai_controller.web.server import app, initialize


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
    return TestClient(app, base_url="https://testserver")


def test_audit_records_signins_chats_and_decisions_without_secrets(tmp_path):
    client = _client(tmp_path)
    failed = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert failed.status_code == 401
    signed_in = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    assert signed_in.status_code == 200

    session = web_server.session_manager.create_session("Host lookup")
    web_server.session_manager.add_entry(session.id, "what is 10.10.10.2", result={"success": True, "output": {"text": "A host."}})
    request = ApprovalRequest(
        action_type="close_alert",
        title="Close the ping",
        summary="Benign",
        status=RequestStatus.DENIED,
        decision=Decision(action="deny", actor="admin"),
    )
    get_queue().store.put(request)

    listed = client.get("/api/audit")
    assert listed.status_code == 200, listed.text
    events = listed.json()["events"]
    kinds = {(item["kind"], item["outcome"]) for item in events}
    assert ("signin", "failed") in kinds
    assert ("signin", "signed_in") in kinds
    assert any(item["kind"] == "chat" and "10.10.10.2" in item["summary"] for item in events)
    assert any(item["kind"] == "action" and item["request_id"] == request.id and "Close the ping" in item["summary"] for item in events)
    assert events[0]["at"] >= events[-1]["at"]

    signed_out = client.post("/api/auth/logout")
    assert signed_out.status_code == 200
    raw = audit_log_path().read_text(encoding="utf-8")
    assert "wrong-password" not in raw
    assert "test-password" not in raw
    assert "signed_out" in raw
