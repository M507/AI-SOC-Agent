"""Elastic Defend host isolation via Kibana Endpoint Security."""

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


def test_isolate_posts_to_kibana_action_api(monkeypatch):
    calls = []

    def fake_request(**kwargs):
        url = kwargs["url"]
        body = kwargs.get("json")
        calls.append({"url": url, "json": body, "method": kwargs["method"]})
        if url.endswith("/api/endpoint/action/isolate"):
            return _response(200, {"data": {"id": "act-iso-1", "status": "pending"}})
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.isolate_endpoint(
        endpoint_id="1cd01db9-be24-4bef-8e7c-e923f0ff78ab",
        hostname="ws-1",
        comment="ransomware note",
        client=_client(),
    )
    assert result["success"] is True
    assert result["provider"] == "elastic"
    assert result["action_id"] == "act-iso-1"
    assert result["endpoint_id"] == "1cd01db9-be24-4bef-8e7c-e923f0ff78ab"
    isolate = calls[0]
    assert isolate["url"] == "https://kibana.example:5601/api/endpoint/action/isolate"
    assert isolate["json"]["endpoint_ids"] == ["1cd01db9-be24-4bef-8e7c-e923f0ff78ab"]
    assert isolate["json"]["comment"] == "ransomware note"


def test_isolate_resolves_hostname_via_metadata(monkeypatch):
    calls = []

    def fake_request(**kwargs):
        url = kwargs["url"]
        params = kwargs.get("params") or {}
        body = kwargs.get("json")
        calls.append({"url": url, "json": body, "params": params, "method": kwargs["method"]})
        if url.endswith("/api/endpoint/metadata"):
            return _response(
                200,
                {
                    "data": [
                        {
                            "metadata": {
                                "agent": {"id": "agent-from-host"},
                                "host": {"hostname": "ws-1", "name": "ws-1"},
                            }
                        }
                    ]
                },
            )
        if url.endswith("/api/endpoint/action/isolate"):
            return _response(200, {"data": {"id": "act-iso-2"}})
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.isolate_endpoint(
        endpoint_id="ws-1",
        hostname="ws-1",
        client=_client(),
    )
    assert result["endpoint_id"] == "agent-from-host"
    meta = next(call for call in calls if call["url"].endswith("/api/endpoint/metadata"))
    assert "host.name" in meta["params"]["kuery"]
    isolate = next(call for call in calls if call["url"].endswith("/api/endpoint/action/isolate"))
    assert isolate["json"]["endpoint_ids"] == ["agent-from-host"]


def test_isolate_falls_back_to_legacy_path(monkeypatch):
    def fake_request(**kwargs):
        url = kwargs["url"]
        if url.endswith("/api/endpoint/action/isolate"):
            return _response(404, text="Not Found")
        if url.endswith("/api/endpoint/isolate"):
            return _response(200, {"data": {"id": "legacy-1"}})
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.isolate_endpoint(
        endpoint_id="1cd01db9-be24-4bef-8e7c-e923f0ff78ab",
        client=_client(),
    )
    assert result["action_id"] == "legacy-1"
    assert result["api_path"] == "/api/endpoint/isolate"


def test_isolate_explains_kibana_auth_failure(monkeypatch):
    def fake_request(**kwargs):
        return _response(401, text="Unauthorized")

    monkeypatch.setattr("requests.request", fake_request)
    with pytest.raises(IntegrationError, match="host-isolation"):
        tools_siem.isolate_endpoint(
            endpoint_id="1cd01db9-be24-4bef-8e7c-e923f0ff78ab",
            client=_client(),
        )


def test_release_posts_unisolate(monkeypatch):
    calls = []

    def fake_request(**kwargs):
        url = kwargs["url"]
        calls.append(url)
        if url.endswith("/api/endpoint/action/unisolate"):
            return _response(200, {"data": {"id": "act-rel-1"}})
        pytest.fail(f"unexpected request {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    result = tools_siem.release_endpoint_isolation(
        endpoint_id="1cd01db9-be24-4bef-8e7c-e923f0ff78ab",
        client=_client(),
    )
    assert result["action_id"] == "act-rel-1"
    assert calls[0].endswith("/api/endpoint/action/unisolate")
