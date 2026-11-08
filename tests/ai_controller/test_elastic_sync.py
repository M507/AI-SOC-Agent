"""Unit tests for Detection as Code Elastic rule sync."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.ai_controller.detection.elastic_sync import push_rule_file
from src.ai_controller.detection.errors import DetectionError
from src.core.errors import IntegrationError


def _rule_file(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "_dac": {
                    "status": "enabled",
                    "rule_id": "rule-1234-5678",
                    "elastic_id": "elastic-abc",
                    "name": "Test Rule",
                },
                "rule": {
                    "name": "Test Rule",
                    "rule_id": "rule-1234-5678",
                    "id": "elastic-abc",
                    "enabled": True,
                    "query": "event.action:login",
                    "language": "kuery",
                    "type": "query",
                    "exceptions_list": [],
                },
                "exception_items": [
                    {
                        "item_id": "sami-rule-123-aaaa",
                        "list_id": "sami-rule-123-exceptions",
                        "type": "simple",
                        "name": "host.name=lab",
                        "namespace_type": "single",
                        "entries": [
                            {
                                "field": "host.name",
                                "operator": "included",
                                "type": "match",
                                "value": "lab",
                            }
                        ],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_push_rule_file_upserts_exceptions_and_updates_rule(tmp_path):
    path = _rule_file(tmp_path / "rule.json")
    http = MagicMock()
    # exception list missing → create; item missing → create; get rule; put rule
    http.get.side_effect = [
        IntegrationError("HTTP 404: missing list"),
        IntegrationError("HTTP 404: missing item"),
        {
            "id": "elastic-abc",
            "rule_id": "rule-1234-5678",
            "name": "Test Rule",
            "enabled": True,
            "query": "event.action:login",
            "language": "kuery",
            "type": "query",
            "revision": 3,
            "immutable": False,
        },
    ]
    http.post.side_effect = [
        {
            "id": "list-1",
            "list_id": "sami-rule-123-exceptions",
            "type": "detection",
            "namespace_type": "single",
        },
        {
            "id": "item-1",
            "item_id": "sami-rule-123-aaaa",
            "list_id": "sami-rule-123-exceptions",
            "type": "simple",
            "namespace_type": "single",
            "entries": [
                {"field": "host.name", "operator": "included", "type": "match", "value": "lab"}
            ],
        },
    ]
    http.put.return_value = {
        "id": "elastic-abc",
        "rule_id": "rule-1234-5678",
        "name": "Test Rule",
        "enabled": True,
        "query": "event.action:login",
        "language": "kuery",
        "type": "query",
        "revision": 4,
        "exceptions_list": [
            {
                "id": "list-1",
                "list_id": "sami-rule-123-exceptions",
                "type": "detection",
                "namespace_type": "single",
            }
        ],
    }

    client = MagicMock()
    client._cases_http.return_value = http

    result = push_rule_file(client, path)
    assert result["synced"] is True
    assert result["revision"] == 4

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["_dac"]["last_synced_hash"] == saved["_dac"]["content_hash"]
    assert saved["_dac"]["revision"] == 4
    assert saved["rule"]["exceptions_list"][0]["list_id"] == "sami-rule-123-exceptions"
    assert http.put.called


def test_push_rule_file_requires_client(tmp_path):
    path = _rule_file(tmp_path / "rule.json")
    with pytest.raises(DetectionError, match="No Elastic cluster"):
        push_rule_file(None, path)
