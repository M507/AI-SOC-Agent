"""Unit tests for alert search by rule name / workflow status."""

from unittest.mock import Mock

import pytest

from src.core.errors import IntegrationError
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem


def _hit(alert_id, *, rule_name, status, verdict=None, rule_id="rule-1"):
    source = {
        "@timestamp": "2026-09-20T12:00:00Z",
        "kibana.alert.rule.name": rule_name,
        "kibana.alert.rule.uuid": rule_id,
        "kibana.alert.workflow_status": status,
        "kibana.alert.severity": "high",
        "signal": {
            "status": status,
            "severity": "high",
            "rule": {"name": rule_name, "id": rule_id, "description": "test rule"},
        },
    }
    if verdict:
        source["signal"]["ai"] = {"verdict": verdict}
    return {"_id": alert_id, "_index": ".alerts-security.alerts-default", "_source": source}


def _client_with_hits(hits):
    http = Mock()
    http.post.return_value = {"hits": {"hits": hits, "total": {"value": len(hits)}}}
    return ElasticSIEMClient(http), http


def _bool_query(http):
    return http.post.call_args.kwargs["json_data"]["query"]["bool"]


def test_normalize_status_aliases():
    assert ElasticSIEMClient._normalize_alert_status("akn") == "acknowledged"
    assert ElasticSIEMClient._normalize_alert_status("ACK") == "acknowledged"
    assert ElasticSIEMClient._normalize_alert_status("closed") == "closed"
    assert ElasticSIEMClient._normalize_alert_status(None) is None


def test_get_security_alerts_filters_by_rule_name_and_acknowledged():
    client, http = _client_with_hits(
        [_hit("a1", rule_name="Suspicious PowerShell", status="acknowledged", verdict="false_positive")]
    )

    alerts = client.get_security_alerts(
        hours_back=48,
        max_alerts=10,
        rule_name="Suspicious PowerShell",
        status_filter="akn",
    )

    assert len(alerts) == 1
    assert alerts[0]["status"] == "acknowledged"
    assert alerts[0]["rule_name"] == "Suspicious PowerShell"
    assert alerts[0]["verdict"] == "false_positive"

    query = _bool_query(http)
    assert any("match_phrase" in str(clause) for clause in query["must"])
    assert any("acknowledged" in str(clause) for clause in query["must"])
    # Historical status should not exclude verdicted alerts
    assert "must_not" not in query or not any(
        clause.get("exists", {}).get("field") == "signal.ai.verdict"
        for clause in query.get("must_not", [])
    )


def test_get_security_alerts_default_excludes_closed_and_investigated():
    client, http = _client_with_hits([])

    client.get_security_alerts(hours_back=24, max_alerts=5)

    query = _bool_query(http)
    must_not = query.get("must_not", [])
    assert any("closed" in str(clause) for clause in must_not)
    assert any(
        clause.get("exists", {}).get("field") == "signal.ai.verdict" for clause in must_not
    )


def test_get_security_alerts_closed_includes_investigated_by_default():
    client, http = _client_with_hits(
        [_hit("c1", rule_name="Brute Force", status="closed", verdict="true_positive")]
    )

    alerts = client.get_security_alerts(
        hours_back=72,
        status_filter="closed",
        rule_name="Brute Force",
    )

    assert len(alerts) == 1
    assert alerts[0]["status"] == "closed"
    query = _bool_query(http)
    assert "must_not" not in query or not any(
        clause.get("exists", {}).get("field") == "signal.ai.verdict"
        for clause in query.get("must_not", [])
    )


def test_get_rule_detections_by_rule_name_and_closed_state():
    client, http = _client_with_hits(
        [_hit("d1", rule_name="Lateral Movement", status="closed", verdict="false_positive")]
    )

    detections = client.get_rule_detections(
        rule_name="Lateral Movement",
        alert_state="closed",
        hours_back=168,
        limit=20,
    )

    assert len(detections) == 1
    assert detections[0]["rule_name"] == "Lateral Movement"
    assert detections[0]["status"] == "closed"
    assert detections[0]["verdict"] == "false_positive"

    query = _bool_query(http)
    assert any("Lateral Movement" in str(clause) for clause in query["must"])
    assert any("closed" in str(clause) for clause in query["must"])


def test_get_rule_detections_requires_rule_identifier():
    client, _http = _client_with_hits([])
    with pytest.raises(IntegrationError, match="rule_id and/or rule_name"):
        client.get_rule_detections(hours_back=24)


def test_tools_get_security_alerts_passes_filters():
    captured = {}

    class Fake:
        def get_security_alerts(self, **kwargs):
            captured.update(kwargs)
            return [
                {
                    "id": "1",
                    "title": "Rule A",
                    "rule_name": "Rule A",
                    "status": "acknowledged",
                    "severity": "medium",
                }
            ]

    result = tools_siem.get_security_alerts(
        hours_back=24,
        max_alerts=5,
        status_filter="akn",
        rule_name="Rule A",
        client=Fake(),
    )

    assert result["success"] is True
    assert result["count"] == 1
    assert captured["status_filter"] == "akn"
    assert captured["rule_name"] == "Rule A"


def test_tools_get_rule_detections_by_name():
    class Fake:
        def get_rule_detections(self, **kwargs):
            assert kwargs["rule_name"] == "Rule B"
            assert kwargs["alert_state"] == "closed"
            assert kwargs["rule_id"] is None
            return [{"id": "x", "status": "closed", "rule_name": "Rule B"}]

    result = tools_siem.get_rule_detections(
        rule_name="Rule B",
        alert_state="closed",
        client=Fake(),
    )

    assert result["success"] is True
    assert result["count"] == 1
    assert result["rule_name"] == "Rule B"


def test_tools_get_rule_detections_requires_identifier():
    with pytest.raises(IntegrationError, match="rule_id and/or rule_name"):
        tools_siem.get_rule_detections(client=Mock())
