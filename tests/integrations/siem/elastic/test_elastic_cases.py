"""Elastic Security cases: Kibana Cases API, full alert body, live cluster."""

from types import SimpleNamespace

import pytest

from src.core.elastic_clusters import derive_kibana_url
from src.core.errors import IntegrationError
from src.integrations.siem.elastic.case_builder import (
    build_elastic_case_description,
    default_case_title,
    kibana_severity,
)
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem


ALERT_HIT = {
    "_id": "alert-22",
    "_index": ".internal.alerts-security.alerts-default-000001",
    "_source": {
        "@timestamp": "2026-08-18T12:00:00Z",
        "message": "Suspicious login from 8.8.8.8",
        "kibana.alert.rule.name": "Suspicious login",
        "kibana.alert.rule.uuid": "rule-9",
        "kibana.alert.rule.description": "Detects impossible travel from a new ASN",
        "kibana.alert.severity": "high",
        "kibana.alert.workflow_status": "open",
        "user": {"name": "sami"},
        "source": {"ip": "8.8.8.8"},
        "host": {"hostname": "vpn-gw"},
        "kibana.alert.ancestors": [{"id": "evt-1"}],
    },
}

EVENT_HIT = {
    "_id": "evt-1",
    "_index": "logs-endpoint.events-default",
    "_source": {
        "@timestamp": "2026-08-18T12:00:00Z",
        "message": "Successful VPN login from 8.8.8.8",
        "host": {"hostname": "vpn-gw"},
    },
}


def _response(status_code=200, body=None, text=""):
    payload = body if body is not None else {}

    def _json():
        if body is None and not text:
            raise ValueError("No JSON")
        return payload

    return SimpleNamespace(
        status_code=status_code,
        text=text or "",
        reason="Unauthorized" if status_code == 401 else "OK",
        json=_json,
    )


def _client():
    return ElasticSIEMClient.from_settings(
        base_url="https://es.example:9200",
        kibana_url="https://kibana.example:5601",
        api_key="test-key",
        verify_ssl=False,
    )


def test_derive_kibana_url_maps_es_port():
    assert derive_kibana_url("https://10.10.10.88:9200") == "https://10.10.10.88:5601"
    assert derive_kibana_url("https://10.10.10.88:9200", "https://kibana.lab:5601/") == "https://kibana.lab:5601"
    assert derive_kibana_url("https://10.10.10.88:5601") == "https://10.10.10.88:5601"


def test_case_title_and_severity_follow_case_standard():
    title = default_case_title(
        alert={"title": "Suspicious login", "created_at": "2026-08-18T12:00:00Z"},
        identity={"username": "sami", "activity": "VPN login"},
    )
    assert title == "VPN login - sami - 2026-08-18"
    assert kibana_severity("crit") == "critical"
    assert kibana_severity("nope") == "high"


def test_case_description_includes_full_alert_and_identity():
    body = build_elastic_case_description(
        notes="Analyst said this was not them.",
        alert={
            "id": "alert-22",
            "title": "Suspicious login",
            "severity": "high",
            "priority": "high",
            "status": "open",
            "verdict": "true_positive",
            "description": "Impossible travel from a new ASN",
            "created_at": "2026-08-18T12:00:00Z",
            "related_entities": ["user:sami", "ip:8.8.8.8", "hostname:vpn-gw"],
            "events": [
                {
                    "id": "evt-1",
                    "timestamp": "2026-08-18T12:00:00Z",
                    "host": "vpn-gw",
                    "message": "Successful VPN login from 8.8.8.8",
                }
            ],
            "comments": [
                {
                    "author": "sami-gpt",
                    "comment": "Filed identity verification",
                    "timestamp": "2026-08-18T12:01:00Z",
                }
            ],
        },
        identity={"username": "sami", "source_ip": "8.8.8.8", "activity": "VPN login"},
    )
    for needle in (
        "Analyst said this was not them.",
        "alert-22",
        "Suspicious login",
        "Impossible travel from a new ASN",
        "user:sami",
        "8.8.8.8",
        "Successful VPN login",
        "Filed identity verification",
        "not the user",
    ):
        assert needle in body


def test_create_elastic_case_posts_kibana_api_with_loaded_alert(monkeypatch):
    calls = []

    def fake_request(**kwargs):
        method = kwargs["method"]
        url = kwargs["url"]
        body = kwargs.get("json")
        calls.append({"method": method, "url": url, "json": body})
        if "/_search" in url:
            values = ((body or {}).get("query") or {}).get("ids", {}).get("values") or []
            hits = [EVENT_HIT] if values == ["evt-1"] else [ALERT_HIT]
            return _response(200, {"hits": {"hits": hits, "total": {"value": len(hits)}}})
        if method == "POST" and url.endswith("/api/cases"):
            return _response(
                200,
                {
                    "id": "elastic-case-1",
                    "title": body["title"],
                    "description": body["description"],
                    "severity": body["severity"],
                    "status": "open",
                    "tags": body["tags"],
                    "owner": "securitySolution",
                },
            )
        if method == "POST" and url.endswith("/comments"):
            return _response(200, {"id": "comment-1", "type": "alert"})
        return _response(200, {})

    monkeypatch.setattr("requests.request", fake_request)

    result = tools_siem.create_elastic_case(
        alert_id="alert-22",
        description="Analyst said this was not them.",
        identity={"username": "sami", "source_ip": "8.8.8.8", "activity": "VPN login"},
        tags=["soc1-triage"],
        client=_client(),
    )

    assert result["success"] is True
    assert result["provider"] == "elastic"
    assert result["case_id"] == "elastic-case-1"
    assert result["alert_attached"] is True
    assert result["alert_id"] == "alert-22"

    create = next(call for call in calls if call["url"].endswith("/api/cases"))
    assert create["method"] == "POST"
    assert create["url"] == "https://kibana.example:5601/api/cases"
    payload = create["json"]
    assert payload["owner"] == "securitySolution"
    assert payload["connector"] == {
        "id": "none",
        "name": "none",
        "type": ".none",
        "fields": None,
    }
    assert payload["settings"]["syncAlerts"] is True
    assert payload["severity"] == "high"
    assert "sami-gpt" in payload["tags"]
    assert "escalated" in payload["tags"]
    assert "identity-verify" in payload["tags"]
    assert "soc1-triage" in payload["tags"]
    for needle in (
        "alert-22",
        "sami",
        "8.8.8.8",
        "Detects impossible travel from a new ASN",
        "Analyst said this was not them.",
        "Suspicious login",
    ):
        assert needle in payload["description"]

    attach = next(call for call in calls if call["url"].endswith("/comments"))
    assert attach["url"] == "https://kibana.example:5601/api/cases/elastic-case-1/comments"
    assert attach["json"]["type"] == "alert"
    assert attach["json"]["alertId"] == ["alert-22"]
    assert attach["json"]["index"] == [".internal.alerts-security.alerts-default-000001"]
    assert attach["json"]["rule"]["id"] == "rule-9"

    searches = [call for call in calls if "/_search" in call["url"]]
    assert searches
    assert all(call["url"].startswith("https://es.example:9200/") for call in searches)


def test_create_elastic_case_still_opens_when_alert_is_missing(monkeypatch):
    calls = []

    def fake_request(**kwargs):
        url = kwargs["url"]
        body = kwargs.get("json")
        calls.append({"url": url, "json": body, "method": kwargs["method"]})
        if "/_search" in url:
            return _response(200, {"hits": {"hits": [], "total": {"value": 0}}})
        if url.endswith("/api/cases"):
            return _response(
                200,
                {
                    "id": "elastic-case-2",
                    "title": body["title"],
                    "description": body["description"],
                    "severity": body["severity"],
                    "status": "open",
                    "tags": body["tags"],
                },
            )
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.create_elastic_case(
        alert_id="missing-alert",
        title="Unauthorized activity: sami",
        description="Analyst said this was not them.",
        client=_client(),
    )
    assert result["case_id"] == "elastic-case-2"
    assert result["alert_attached"] is False
    create = next(call for call in calls if call["url"].endswith("/api/cases"))
    assert "missing-alert" in create["json"]["description"]
    assert not any(call["url"].endswith("/comments") for call in calls)


def test_create_elastic_case_survives_attach_failure(monkeypatch):
    def fake_request(**kwargs):
        url = kwargs["url"]
        body = kwargs.get("json")
        if "/_search" in url:
            return _response(200, {"hits": {"hits": [ALERT_HIT], "total": {"value": 1}}})
        if url.endswith("/api/cases"):
            return _response(
                200,
                {
                    "id": "elastic-case-3",
                    "title": body["title"],
                    "description": body["description"],
                    "severity": "high",
                    "status": "open",
                    "tags": body["tags"],
                },
            )
        if url.endswith("/comments"):
            return _response(400, {"statusCode": 400, "message": "cannot attach alert"})
        return _response(200, {})

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.create_elastic_case(alert_id="alert-22", client=_client())
    assert result["success"] is True
    assert result["case_id"] == "elastic-case-3"
    assert result["alert_attached"] is False
    assert result["attach_error"]


def test_create_elastic_case_kibana_401_explains_api_key(monkeypatch):
    def fake_request(**kwargs):
        url = kwargs["url"]
        if "/_search" in url:
            return _response(200, {"hits": {"hits": [ALERT_HIT], "total": {"value": 1}}})
        return _response(
            401,
            {
                "statusCode": 401,
                "error": "Unauthorized",
                "message": "security_exception: unable to authenticate",
            },
        )

    monkeypatch.setattr("requests.request", fake_request)
    with pytest.raises(IntegrationError, match="Kibana API key"):
        tools_siem.create_elastic_case(alert_id="alert-22", client=_client())


def test_create_elastic_case_tool_requires_elastic_client():
    with pytest.raises(IntegrationError, match="does not support Elastic Security cases"):
        tools_siem.create_elastic_case(alert_id="alert-22", client=object())


def _live_client():
    from src.core.elastic_clusters import client_for_cluster, get_cluster, probe_cluster

    cluster = get_cluster()
    if not cluster or not cluster.base_url:
        pytest.skip("No Elastic cluster configured")
    probe = probe_cluster(cluster)
    if not probe.get("ok"):
        pytest.skip(f"Elastic cluster is not reachable: {probe.get('message')}")
    return client_for_cluster(cluster)


def test_live_alert_details_are_enough_to_open_an_elastic_case():
    """ES-only: a real alert can be turned into a case description with full details."""
    client = _live_client()
    try:
        alerts = client.get_security_alerts(hours_back=72, max_alerts=1)
    except IntegrationError as exc:
        pytest.skip(f"Elastic alerts are not usable: {exc}")
    if not alerts:
        pytest.skip("No recent Elastic alerts to use as a case fixture")

    alert_id = alerts[0]["id"]
    detail = client.get_security_alert_by_id(alert_id, include_detections=True)
    body = build_elastic_case_description(
        notes="Analyst said this was not them.",
        alert=detail,
        identity={"username": "sami", "activity": "VPN login"},
    )
    assert alert_id in body
    assert "Analyst said this was not them." in body
    assert detail.get("title") in body or "VPN login" in body
    assert "## Alert" in body


def test_live_create_elastic_case_includes_real_alert_then_deletes():
    """Kibana Cases API: open a case from a real alert, then delete it."""
    client = _live_client()
    try:
        alerts = client.get_security_alerts(hours_back=72, max_alerts=1)
    except IntegrationError as exc:
        pytest.skip(f"Elastic alerts are not usable: {exc}")
    alert_id = alerts[0]["id"] if alerts else None

    try:
        created = tools_siem.create_elastic_case(
            title="SamiGPT skill test — delete me",
            description="Temporary case from tests/integrations/siem.",
            alert_id=alert_id,
            tags=["sami-skill-test"],
            severity="low",
            identity={"username": "sami", "activity": "integration-test"} if alert_id else None,
            client=client,
        )
    except IntegrationError as exc:
        pytest.skip(f"Kibana Cases API is not usable: {exc}")

    try:
        assert created["success"] is True
        assert created["provider"] == "elastic"
        assert created["case_id"]
        assert "Temporary case from tests/integrations/siem." in (created.get("description") or "")
        if alert_id:
            assert alert_id in (created.get("description") or "")
            assert created.get("alert_id") == alert_id
    finally:
        case_id = created.get("case_id")
        if case_id:
            client._cases_http().delete("/api/cases", json_data={"ids": [case_id]})
