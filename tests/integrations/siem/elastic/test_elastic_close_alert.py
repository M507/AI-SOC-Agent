"""Closing Elastic Security alerts via Kibana Detection Engine status API."""

from types import SimpleNamespace

import pytest

from src.core.errors import IntegrationError
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem


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


def test_close_alert_posts_kibana_status_and_sets_verdict(monkeypatch):
    calls = []
    client = _client()

    def fake_request(**kwargs):
        url = kwargs["url"]
        body = kwargs.get("json")
        calls.append({"url": url, "json": body, "method": kwargs["method"]})
        if url.endswith("/api/detection_engine/signals/status"):
            return _response(200, {"updated": 1, "total": 1, "failures": []})
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)

    def fake_verdict(alert_id, verdict, comment=None):
        return {
            "success": True,
            "alert_id": alert_id,
            "verdict": verdict,
            "comment": comment,
            "alert": {
                "id": alert_id,
                "status": "closed",
                "verdict": verdict,
            },
        }

    monkeypatch.setattr(client, "update_alert_verdict", fake_verdict)

    result = tools_siem.close_alert(
        alert_id="alert-9",
        reason="benign_true_positive",
        comment="known scanner",
        client=client,
    )

    assert result["success"] is True
    assert result["status"] == "closed"
    assert result["reason"] == "benign_true_positive"
    assert result["alert_id"] == "alert-9"
    assert len(calls) == 1
    close_call = calls[0]
    assert close_call["url"] == "https://kibana.example:5601/api/detection_engine/signals/status"
    assert close_call["json"] == {
        "signal_ids": ["alert-9"],
        "status": "closed",
        "reason": "benign_positive",
    }


def test_close_alert_maps_false_positive_reason(monkeypatch):
    calls = []
    client = _client()

    def fake_request(**kwargs):
        calls.append(kwargs.get("json"))
        return _response(200, {"updated": 1, "failures": []})

    monkeypatch.setattr("requests.request", fake_request)
    monkeypatch.setattr(
        client,
        "update_alert_verdict",
        lambda *args, **kwargs: {"alert": {"id": "a1", "status": "closed"}},
    )

    result = client.close_alert("a1", reason="FP", comment="noise")
    assert result["status"] == "closed"
    assert result["reason"] == "false_positive"
    assert calls[0]["reason"] == "false_positive"
    assert calls[0]["status"] == "closed"


def test_close_alert_fails_when_kibana_rejects(monkeypatch):
    client = _client()

    def fake_request(**kwargs):
        return _response(401, {"error": "Unauthorized", "message": "nope", "statusCode": 401})

    monkeypatch.setattr("requests.request", fake_request)

    with pytest.raises(IntegrationError) as exc:
        client.close_alert("alert-9", reason="false_positive")
    assert "Failed to close alert alert-9" in str(exc.value)
    assert "Kibana" in str(exc.value)


def test_close_alert_fails_when_kibana_updates_zero(monkeypatch):
    client = _client()

    def fake_request(**kwargs):
        return _response(200, {"updated": 0, "total": 0, "failures": []})

    monkeypatch.setattr("requests.request", fake_request)

    with pytest.raises(IntegrationError) as exc:
        client.close_alert("missing-alert")
    assert "updated 0 alerts" in str(exc.value)


def test_close_alert_still_succeeds_if_verdict_write_fails(monkeypatch):
    client = _client()

    def fake_request(**kwargs):
        return _response(200, {"updated": 1, "failures": []})

    monkeypatch.setattr("requests.request", fake_request)
    monkeypatch.setattr(
        client,
        "update_alert_verdict",
        lambda *args, **kwargs: (_ for _ in ()).throw(IntegrationError("verdict boom")),
    )
    monkeypatch.setattr(
        client,
        "get_security_alert_by_id",
        lambda *args, **kwargs: {"id": "alert-9", "status": "closed"},
    )

    result = client.close_alert("alert-9", reason="false_positive", comment="fp")
    assert result["success"] is True
    assert result["status"] == "closed"
    assert result["alert"]["status"] == "closed"
