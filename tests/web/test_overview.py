"""Landing dashboard counts from the approval queue."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from src.ai_controller.approval_queue.models import ApprovalRequest, RequestStatus
from src.ai_controller.web.auth import COOKIE_NAME, SessionManagerAuth, WebAuthConfig, _login_failures, _sessions
from src.ai_controller.web.overview import build_overview
from src.ai_controller.web.server import app, initialize
from src.ai_controller.web import auth as auth_mod


def _request(action_type, status, created_at, payload=None, title="Request"):
    return ApprovalRequest(
        action_type=action_type,
        title=title,
        summary="",
        status=status,
        payload=payload or {},
        created_at=created_at,
        updated_at=created_at,
    )


def test_overview_counts_decisions_detection_and_response():
    now = datetime(2026, 9, 29, 12, 0, 0)
    older = now - timedelta(days=10)
    requests = [
        _request("close_alert", RequestStatus.EXECUTED, now, {"reason": "false_positive"}, "FP"),
        _request("close_alert", RequestStatus.EXECUTED, now, {"reason": "benign_true_positive"}, "BTP"),
        _request("close_alert", RequestStatus.PENDING, now, {"reason": "false_positive"}, "Waiting close"),
        _request("escalate", RequestStatus.EXECUTED, now, title="Escalate"),
        _request("fine_tune", RequestStatus.INFORMATIONAL, now, title="Tune"),
        _request("visibility", RequestStatus.INFORMATIONAL, now, title="Gap"),
        _request("runbook_gap", RequestStatus.INFORMATIONAL, older, title="Old gap"),
        _request("isolate_endpoint", RequestStatus.EXECUTED, now, title="Isolate"),
        _request("create_case", RequestStatus.DENIED, now, title="Denied case"),
        _request("collect_forensics", RequestStatus.AWAITING_INTEGRATION, older, title="Waiting EDR"),
        _request("kill_process", RequestStatus.FAILED, now, title="Kill failed"),
    ]

    class Dated:
        def __init__(self, created_at):
            self.created_at = created_at

    body = build_overview(
        requests,
        [Dated(now), Dated(older)],
        [Dated(now)],
        {"cost_label": "$1.20"},
        "7d",
        now=now,
        spend_events=[
            {
                "at": now.isoformat(),
                "cost_usd": 1.2,
                "priced": True,
                "usage_reported": True,
            },
            {
                "at": now.isoformat(),
                "cost_usd": None,
                "priced": False,
                "usage_reported": True,
            },
        ],
    )
    counts = {card["id"]: card["count"] for card in body["decisions"]}
    assert counts == {"false_positive": 1, "benign_true_positive": 1, "escalations": 1}
    assert body["waiting"][0]["count"] == 1
    detection = {card["id"]: card["count"] for card in body["detection"]}
    assert detection == {"fine_tune": 1, "visibility": 1, "runbook_gap": 0}
    response = {card["id"]: card["count"] for card in body["response"]}
    assert response["isolate_endpoint"] == 1
    assert response["create_case"] == 0
    assert body["work"][0]["count"] == 1
    assert body["work"][0]["go"] == "sessions"
    assert body["work"][1]["count"] == 1
    assert body["work"][1]["go"] == "autoruns"
    assert body["work"][2]["value"] == "$1.20"
    assert body["work"][2]["go"] == "cost"
    assert body["attention"] == {"pending": 1, "awaiting": 1, "informational": 3}
    outcomes = {card["id"]: card["count"] for card in body["outcomes"]}
    assert outcomes == {"executed": 4, "denied": 1, "failed": 1, "acknowledged": 0}
    today = now.date().isoformat()
    today_row = next(row for row in body["activity"] if row["bucket"] == today)
    assert today_row["filed"] == 9
    assert today_row["settled"] == 6
    assert body["series_unit"] == "day"
    assert body["series_capped"] is False
    spend_today = next(row for row in body["spend_series"] if row["bucket"] == today)
    assert spend_today["cost_usd"] == 1.2
    assert body["spend_unpriced"] is True
    assert any(row["title"] == "FP" for row in body["recent"])
    assert all(row["title"] != "Waiting close" for row in body["recent"])


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
            password="test-password",
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


def test_overview_route_rejects_unknown_range_and_returns_cards(tmp_path):
    client = _client(tmp_path)
    bad = client.get("/api/overview?range=year")
    assert bad.status_code == 400
    ok = client.get("/api/overview?range=all")
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["success"] is True
    assert [card["id"] for card in body["decisions"]] == [
        "false_positive",
        "benign_true_positive",
        "escalations",
    ]
    assert body["detection"]
    assert body["response"]
    assert body["work"]
    assert "recent" in body
    assert "attention" in body
    assert "activity" in body
    assert "outcomes" in body
    assert "spend_series" in body


def test_overview_all_uses_weeks_and_keeps_latest_buckets():
    now = datetime(2026, 9, 29, 12, 0, 0)
    old = now - timedelta(days=400)
    requests = [
        _request("close_alert", RequestStatus.EXECUTED, old, {"reason": "false_positive"}, "Old FP"),
        _request("escalate", RequestStatus.EXECUTED, now, title="Now"),
    ]
    body = build_overview(requests, [], [], {"cost_label": "$0"}, "all", now=now)
    assert body["series_unit"] == "week"
    assert body["series_capped"] is True
    assert len(body["activity"]) == 30
    assert sum(row["filed"] for row in body["activity"]) == 1
    counts = {card["id"]: card["count"] for card in body["decisions"]}
    assert counts["false_positive"] == 1
    assert counts["escalations"] == 1
