"""Unit tests for get_alert_notes (Kibana Security Solution Notes API)."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.core.errors import IntegrationError
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem


EXAMPLE_ALERT_ID = (
    "0a3dd0aa0508acf0b39b99e85c63a39a7af1cc476c98b35ee4e09fe39871f46c"
)

NOTE_RESPONSE = {
    "totalCount": 1,
    "notes": [
        {
            "noteId": "note-1",
            "note": "10.10.10.7 is the admin's macos...",
            "eventId": EXAMPLE_ALERT_ID,
            "timelineId": "",
            "created": 1720000000000,
            "createdBy": "analyst@example.com",
            "updated": 1720000000000,
            "updatedBy": "analyst@example.com",
            "version": "WzEsMV0=",
        }
    ],
}


def _client():
    return ElasticSIEMClient.from_settings(
        base_url="https://es.example:9200",
        kibana_url="https://kibana.example:5601",
        api_key="test-key",
        verify_ssl=False,
    )


def test_get_alert_notes_calls_kibana_note_api():
    client = _client()
    kibana = client._cases_http()
    captured = {}

    def fake_get(endpoint, params=None, extra_headers=None):
        captured["endpoint"] = endpoint
        captured["params"] = params
        captured["extra_headers"] = extra_headers
        return NOTE_RESPONSE

    with patch.object(kibana, "get", side_effect=fake_get):
        # Ensure client uses the same kibana instance we patched.
        with patch.object(client, "_cases_http", return_value=kibana):
            result = client.get_alert_notes(alert_id=EXAMPLE_ALERT_ID)

    assert captured["endpoint"] == "/api/note"
    assert captured["params"] == {"documentIds": [EXAMPLE_ALERT_ID]}
    assert captured["extra_headers"] == {"Elastic-Api-Version": "2023-10-31"}
    assert result["success"] is True
    assert result["total_count"] == 1
    assert result["alert_ids"] == [EXAMPLE_ALERT_ID]
    assert result["note_texts"] == ["10.10.10.7 is the admin's macos..."]
    note = result["notes"][0]
    assert note["note_id"] == "note-1"
    assert note["event_id"] == EXAMPLE_ALERT_ID
    assert note["timeline_id"] == ""
    assert note["created_by"] == "analyst@example.com"
    assert note["created_iso"].endswith("Z")


def test_get_alert_notes_batches_alert_ids():
    client = _client()
    kibana = client._cases_http()
    captured = {}

    def fake_get(endpoint, params=None, extra_headers=None):
        captured["params"] = params
        return {"totalCount": 0, "notes": []}

    with patch.object(kibana, "get", side_effect=fake_get):
        with patch.object(client, "_cases_http", return_value=kibana):
            result = client.get_alert_notes(
                alert_ids=["a1", "a2", "a1"],
                alert_id="a3",
            )

    assert captured["params"] == {"documentIds": ["a1", "a2", "a3"]}
    assert result["alert_ids"] == ["a1", "a2", "a3"]
    assert result["total_count"] == 0
    assert result["notes"] == []


def test_get_alert_notes_requires_ids():
    client = _client()
    with pytest.raises(IntegrationError, match="alert_id or alert_ids"):
        client.get_alert_notes()


def test_tools_siem_get_alert_notes_wrapper():
    client = SimpleNamespace(
        get_alert_notes=lambda **kwargs: {
            "success": True,
            "alert_ids": [EXAMPLE_ALERT_ID],
            "total_count": 1,
            "notes": [{"note": "hello", "event_id": EXAMPLE_ALERT_ID}],
            "note_texts": ["hello"],
        }
    )
    result = tools_siem.get_alert_notes(alert_id=EXAMPLE_ALERT_ID, client=client)
    assert result["success"] is True
    assert result["note_texts"] == ["hello"]


def test_tools_siem_get_alert_notes_requires_client():
    with pytest.raises(IntegrationError, match="SIEM client not provided"):
        tools_siem.get_alert_notes(alert_id=EXAMPLE_ALERT_ID)


def test_get_security_alert_by_id_includes_kibana_notes():
    client = _client()
    alert_hit = {
        "hits": {
            "hits": [
                {
                    "_id": EXAMPLE_ALERT_ID,
                    "_index": ".internal.alerts-security.alerts-default-000001",
                    "_source": {
                        "@timestamp": "2026-08-18T12:00:00Z",
                        "kibana.alert.rule.name": "Suspicious login",
                        "kibana.alert.severity": "high",
                        "kibana.alert.workflow_status": "open",
                        "signal": {"ai": {"verdict": "", "comments": {"comment": []}}},
                    },
                }
            ]
        }
    }

    with patch.object(client, "_search_with_fallback", return_value=alert_hit):
        with patch.object(
            client,
            "get_alert_notes",
            return_value={
                "success": True,
                "alert_ids": [EXAMPLE_ALERT_ID],
                "total_count": 1,
                "notes": [
                    {
                        "note_id": "note-1",
                        "note": "10.10.10.7 is the admin's macos...",
                        "event_id": EXAMPLE_ALERT_ID,
                    }
                ],
                "note_texts": ["10.10.10.7 is the admin's macos..."],
            },
        ) as notes_mock:
            alert = client.get_security_alert_by_id(
                EXAMPLE_ALERT_ID, include_detections=False
            )

    notes_mock.assert_called_once_with(alert_id=EXAMPLE_ALERT_ID)
    assert alert["id"] == EXAMPLE_ALERT_ID
    assert alert["notes_total_count"] == 1
    assert alert["note_texts"] == ["10.10.10.7 is the admin's macos..."]
    assert alert["notes"][0]["note"] == "10.10.10.7 is the admin's macos..."


def test_get_security_alert_by_id_survives_notes_failure():
    client = _client()
    alert_hit = {
        "hits": {
            "hits": [
                {
                    "_id": EXAMPLE_ALERT_ID,
                    "_index": ".internal.alerts-security.alerts-default-000001",
                    "_source": {
                        "@timestamp": "2026-08-18T12:00:00Z",
                        "kibana.alert.rule.name": "Suspicious login",
                        "kibana.alert.severity": "medium",
                        "kibana.alert.workflow_status": "open",
                    },
                }
            ]
        }
    }

    with patch.object(client, "_search_with_fallback", return_value=alert_hit):
        with patch.object(
            client, "get_alert_notes", side_effect=IntegrationError("kibana down")
        ):
            alert = client.get_security_alert_by_id(
                EXAMPLE_ALERT_ID, include_detections=False
            )

    assert alert["id"] == EXAMPLE_ALERT_ID
    assert alert["notes"] == []
    assert alert["note_texts"] == []
    assert alert["notes_total_count"] == 0
