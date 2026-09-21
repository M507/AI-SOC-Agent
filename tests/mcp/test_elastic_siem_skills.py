"""Elastic / ELK MCP skills: catalog, MCP filter/call, and live cluster checks."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.siem import QueryResult, SiemEvent, SourceType
from src.core.skill_vector import (
    CASE_SKILLS,
    SIEM_SKILLS,
    SKILL_TO_SOLUTIONS,
    catalog_payload,
    is_skill_allowed,
)
from src.mcp.http_server import create_mcp_http_app
from src.mcp.mcp_server import SamiGPTMCPServer

TOKEN = "test-mcp-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class FakeSIEM:
    """Minimal SIEM client for MCP tool execution tests."""

    def __init__(self):
        self.last_security_alerts_kwargs = None
        self.last_rule_detections_kwargs = None

    def search_security_events(self, query: str, limit: int = 100) -> QueryResult:
        return QueryResult(
            query=query,
            total_count=1,
            events=[
                SiemEvent(
                    id="evt-1",
                    timestamp=datetime.now(timezone.utc),
                    source_type=SourceType.OTHER,
                    message=f"matched {query}",
                    host="lab-host",
                )
            ],
        )

    def get_security_alerts(self, **kwargs):
        self.last_security_alerts_kwargs = kwargs
        return [
            {
                "id": "alert-1",
                "title": "Suspicious login",
                "rule_name": kwargs.get("rule_name") or "Suspicious login",
                "severity": "high",
                "status": kwargs.get("status_filter") or "open",
                "@timestamp": "2026-08-17T00:00:00Z",
            }
        ]

    def get_rule_detections(self, **kwargs):
        self.last_rule_detections_kwargs = kwargs
        return [
            {
                "id": "det-1",
                "alert_id": "det-1",
                "status": kwargs.get("alert_state") or "closed",
                "rule_name": kwargs.get("rule_name") or "Rule X",
                "timestamp": "2026-08-17T00:00:00Z",
            }
        ]

    def get_alert_notes(self, alert_id=None, alert_ids=None):
        ids = list(alert_ids or [])
        if alert_id and alert_id not in ids:
            ids.append(alert_id)
        return {
            "success": True,
            "alert_ids": ids,
            "total_count": 0,
            "notes": [],
            "note_texts": [],
        }

    def get_security_alert_by_id(self, alert_id, include_detections=True):
        alert = {
            "id": alert_id,
            "title": "Suspicious login",
            "severity": "high",
            "status": "open",
            "verdict": "",
            "description": "test",
            "created_at": "2026-08-17T00:00:00Z",
            "updated_at": "2026-08-17T00:00:00Z",
            "related_entities": [],
            "comments": [],
            "events": [],
            "notes": [],
            "note_texts": [],
            "notes_total_count": 0,
        }
        if include_detections:
            alert["detections"] = []
        return alert

    def create_security_case(self, **kwargs):
        return {
            "case_id": "elastic-case-1",
            "title": kwargs.get("title") or "Unauthorized activity",
            "description": kwargs.get("description") or "full alert",
            "severity": kwargs.get("severity") or "high",
            "status": "open",
            "tags": kwargs.get("tags") or [],
            "alert_id": kwargs.get("alert_id"),
            "alert_attached": True,
            "case": {"id": "elastic-case-1"},
        }


def _mcp_client(siem=None) -> TestClient:
    server = SamiGPTMCPServer(siem_client=siem if siem is not None else FakeSIEM())
    app = create_mcp_http_app(server, api_token=TOKEN)
    return TestClient(app, base_url="https://testserver")


def test_catalog_lists_elk_and_iris_skill_groups():
    catalog = catalog_payload()
    names = [group["name"] for group in catalog["groups"]]
    assert "IRIS skills" in names
    assert "TheHive skills" in names
    assert "Elastic / ELK skills" in names
    assert "EDR skills" in names
    elk = next(group for group in catalog["groups"] if group["id"] == "SIEM")
    iris = next(group for group in catalog["groups"] if group["id"] == "IRIS")
    assert [skill["id"] for skill in elk["skills"]] == list(SIEM_SKILLS)
    assert [skill["id"] for skill in iris["skills"]] == list(CASE_SKILLS)
    assert all(skill["label"] and skill["label"] != skill["id"] for skill in elk["skills"])
    assert SKILL_TO_SOLUTIONS["create_case"] == ("IRIS", "TH")
    assert SKILL_TO_SOLUTIONS["create_elastic_case"] == ("SIEM",)
    assert SKILL_TO_SOLUTIONS["isolate_endpoint"] == ("SIEM", "EDR")
    assert SKILL_TO_SOLUTIONS["get_recent_alerts"] == ("SIEM",)
    assert SKILL_TO_SOLUTIONS["get_alert_notes"] == ("SIEM",)
    assert "get_alert_notes" in SIEM_SKILLS
    assert any(skill["id"] == "get_alert_notes" for skill in elk["skills"])
    assert any(
        skill["id"] == "get_alert_notes" and skill["label"] == "Get Alert Notes"
        for skill in elk["skills"]
    )


def test_catalog_elk_skills_match_registered_mcp_siem_tools():
    server = SamiGPTMCPServer(siem_client=FakeSIEM())
    registered = {name for name in server.tools if name in SIEM_SKILLS}
    assert set(SIEM_SKILLS) == registered


def test_mcp_lists_elk_skills_when_siem_enabled(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:N/TH:N/SIEM:Y/EDR:N/CTI:N/KB:N/ENG:N/RB:N/AG:N/RU:N",
    )
    client = _mcp_client()
    response = client.get("/tools", headers=AUTH)
    assert response.status_code == 200
    names = {tool["name"] for tool in response.json().get("tools") or []}
    assert set(SIEM_SKILLS) <= names
    assert "isolate_endpoint" in names
    assert "create_case" not in names
    assert "list_rules" not in names


def test_mcp_hides_elk_skills_when_siem_disabled(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:Y/TH:N/SIEM:N/EDR:N/CTI:N/KB:N/ENG:N/RB:N/AG:N/RU:N",
    )
    client = _mcp_client()
    names = {tool["name"] for tool in client.get("/tools", headers=AUTH).json().get("tools") or []}
    assert not set(SIEM_SKILLS) & names
    assert is_skill_allowed("create_case", "MSV:1/IRIS:Y/TH:N/SIEM:N")


def test_mcp_search_security_events_returns_results(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/SIEM:Y",
    )
    client = _mcp_client()
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "search_security_events",
                "arguments": {"query": "host:lab-host", "limit": 5},
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "error" not in body
    text = body["result"]["content"][0]["text"]
    assert "evt-1" in text
    assert "success" in text


def test_mcp_create_elastic_case_runs_when_siem_enabled(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:N/TH:N/SIEM:Y",
    )
    client = _mcp_client()
    names = {tool["name"] for tool in client.get("/tools", headers=AUTH).json().get("tools") or []}
    assert "create_elastic_case" in names
    assert "create_case" not in names
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "create_elastic_case",
                "arguments": {
                    "alert_id": "alert-22",
                    "description": "Analyst said this was not them.",
                    "username": "sami",
                    "source_ip": "8.8.8.8",
                },
            },
        },
    )
    assert response.status_code == 200, response.text
    text = response.json()["result"]["content"][0]["text"]
    assert "elastic-case-1" in text
    assert "elastic" in text


def test_mcp_get_recent_alerts_groups_uninvestigated(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/SIEM:Y",
    )
    client = _mcp_client()
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "get_recent_alerts", "arguments": {"hours_back": 1}},
        },
    )
    assert response.status_code == 200, response.text
    text = response.json()["result"]["content"][0]["text"]
    assert "Suspicious login" in text
    assert "uninvestigated_alerts" in text


def test_mcp_rejects_disabled_elk_skill(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/SIEM:N",
    )
    client = _mcp_client()
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "search_security_events",
                "arguments": {"query": "*"},
            },
        },
    )
    assert response.status_code == 200
    error = response.json().get("error") or {}
    assert error.get("code") == -32601
    assert "disabled" in error.get("message", "").lower()


def test_mcp_get_security_alerts_passes_rule_and_status_filters(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/SIEM:Y",
    )
    fake = FakeSIEM()
    client = _mcp_client(siem=fake)
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "get_security_alerts",
                "arguments": {
                    "hours_back": 72,
                    "max_alerts": 5,
                    "rule_name": "Suspicious PowerShell",
                    "status_filter": "akn",
                    "include_investigated": True,
                },
            },
        },
    )
    assert response.status_code == 200, response.text
    assert "error" not in response.json()
    assert fake.last_security_alerts_kwargs is not None
    assert fake.last_security_alerts_kwargs["rule_name"] == "Suspicious PowerShell"
    assert fake.last_security_alerts_kwargs["status_filter"] == "akn"
    assert fake.last_security_alerts_kwargs["include_investigated"] is True
    text = response.json()["result"]["content"][0]["text"]
    assert "Suspicious PowerShell" in text or "acknowledged" in text or "alert-1" in text


def test_mcp_get_rule_detections_by_rule_name(monkeypatch):
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/SIEM:Y",
    )
    fake = FakeSIEM()
    client = _mcp_client(siem=fake)
    response = client.post(
        "/rpc",
        headers=AUTH,
        json={
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "get_rule_detections",
                "arguments": {
                    "rule_name": "Lateral Movement",
                    "alert_state": "closed",
                    "hours_back": 168,
                },
            },
        },
    )
    assert response.status_code == 200, response.text
    assert "error" not in response.json()
    assert fake.last_rule_detections_kwargs is not None
    assert fake.last_rule_detections_kwargs["rule_name"] == "Lateral Movement"
    assert fake.last_rule_detections_kwargs["alert_state"] == "closed"
    assert fake.last_rule_detections_kwargs.get("rule_id") in (None, "")
    text = response.json()["result"]["content"][0]["text"]
    assert "Lateral Movement" in text or "det-1" in text


def _live_es_client():
    from dataclasses import replace

    import pytest

    from src.core.elastic_clusters import client_for_cluster, get_cluster, probe_cluster

    cluster = get_cluster()
    if not cluster or not cluster.base_url:
        pytest.skip("No Elastic cluster configured")
    url = cluster.base_url.rstrip("/")
    if url.endswith(":5601"):
        cluster = replace(cluster, base_url=url[:-5] + ":9200")
    probe = probe_cluster(cluster)
    if not probe.get("ok") or probe.get("kind") != "elasticsearch":
        pytest.skip("Elasticsearch is not reachable for live SIEM tests")
    return client_for_cluster(cluster)


def test_live_elastic_search_security_events():
    import pytest

    from src.core.errors import IntegrationError

    client = _live_es_client()
    try:
        result = client.search_security_events(
            query='{"query": {"match_all": {}}, "size": 1}',
            limit=1,
        )
    except IntegrationError as exc:
        pytest.skip(f"Elastic search is not usable: {type(exc).__name__}")
    assert result.total_count >= 0
    assert isinstance(result.events, list)
    assert len(result.events) <= 1


def test_live_elastic_get_security_alerts():
    import pytest

    from src.core.errors import IntegrationError

    client = _live_es_client()
    try:
        alerts = client.get_security_alerts(hours_back=24, max_alerts=5)
    except IntegrationError as exc:
        pytest.skip(f"Elastic alerts are not usable: {type(exc).__name__}")
    assert isinstance(alerts, list)
