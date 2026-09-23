"""Unit tests for Lucene / EQL / DSL / ES|QL search skills."""

import json
from unittest.mock import Mock

import pytest

from src.core.errors import IntegrationError
from src.core.skill_vector import SIEM_SKILLS, human_skill_label
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem


def _search_hit(event_id="evt-1", host="lab-host", message="powershell ran"):
    return {
        "_id": event_id,
        "_index": "logs-endpoint.events.process-default",
        "_source": {
            "@timestamp": "2026-09-20T12:00:00Z",
            "message": message,
            "host": {"name": host},
            "user": {"name": "alice"},
            "source": {"ip": "10.0.0.5"},
            "process": {"name": "powershell.exe"},
        },
    }


def test_query_skills_are_registered_in_siem_catalog():
    for skill in (
        "search_kql_query",
        "search_lucene_query",
        "search_eql_query",
        "search_dsl_query",
        "search_esql_query",
    ):
        assert skill in SIEM_SKILLS
    assert human_skill_label("search_eql_query") == "Run an EQL search"
    assert human_skill_label("search_esql_query") == "Run an ES|QL search"


def test_search_lucene_query_builds_query_string():
    http = Mock()
    http.post.return_value = {"hits": {"hits": [_search_hit()], "total": {"value": 1}}}
    client = ElasticSIEMClient(http)

    result = client.search_lucene_query(
        'process.name:powershell.exe AND host.name:lab-host',
        limit=10,
        hours_back=24,
    )

    assert result.total_count == 1
    assert result.events[0].host == "lab-host"
    body = http.post.call_args.kwargs["json_data"]
    assert body["query"]["bool"]["must"][0]["query_string"]["query"].startswith("process.name:")
    assert any("now-24h" in str(clause) for clause in body["query"]["bool"]["must"])


def test_search_eql_query_posts_to_eql_endpoint():
    http = Mock()
    http.post.return_value = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "events": [_search_hit("eql-1")],
        }
    }
    client = ElasticSIEMClient(http)

    result = client.search_eql_query(
        'process where process.name == "cmd.exe"',
        limit=25,
        hours_back=12,
    )

    assert result.total_count == 1
    assert result.events[0].id == "eql-1"
    endpoint = http.post.call_args.args[0]
    assert endpoint.endswith("/_eql/search")
    body = http.post.call_args.kwargs["json_data"]
    assert body["query"].startswith("process where")
    assert body["size"] == 25
    assert body["filter"]["range"]["@timestamp"]["gte"] == "now-12h"


def test_search_dsl_query_requires_json_object():
    client = ElasticSIEMClient(Mock())
    with pytest.raises(IntegrationError, match="JSON"):
        client.search_dsl_query("not-json")


def test_search_dsl_query_accepts_json_body():
    http = Mock()
    http.post.return_value = {"hits": {"hits": [_search_hit("dsl-1")], "total": {"value": 1}}}
    client = ElasticSIEMClient(http)

    dsl = json.dumps({"query": {"term": {"host.name": "lab-host"}}})
    result = client.search_dsl_query(dsl, limit=5, hours_back=6)

    assert result.events[0].id == "dsl-1"
    body = http.post.call_args.kwargs["json_data"]
    assert body["size"] == 5
    assert "bool" in body["query"]


def test_search_esql_query_appends_limit_and_maps_rows():
    http = Mock()
    http.post.return_value = {
        "columns": [
            {"name": "@timestamp"},
            {"name": "host.name"},
            {"name": "message"},
        ],
        "values": [
            ["2026-09-20T12:00:00Z", "lab-host", "hello"],
        ],
    }
    client = ElasticSIEMClient(http)

    result = client.search_esql_query(
        'FROM logs-* | WHERE host.name == "lab-host" | KEEP @timestamp, host.name, message',
        limit=20,
    )

    assert result.total_count == 1
    assert result.events[0].host == "lab-host"
    assert "hello" in result.events[0].message
    endpoint = http.post.call_args.args[0]
    assert endpoint == "/_query"
    sent = http.post.call_args.kwargs["json_data"]["query"]
    assert "LIMIT 20" in sent


def test_tools_wrappers_delegate():
    class Fake:
        def search_lucene_query(self, **kwargs):
            from datetime import datetime, timezone
            from src.api.siem import QueryResult, SiemEvent, SourceType

            return QueryResult(
                query=kwargs["lucene_query"],
                total_count=1,
                events=[
                    SiemEvent(
                        id="1",
                        timestamp=datetime.now(timezone.utc),
                        source_type=SourceType.OTHER,
                        message="ok",
                    )
                ],
            )

        def search_eql_query(self, **kwargs):
            return self.search_lucene_query(lucene_query=kwargs["eql_query"])

        def search_dsl_query(self, **kwargs):
            return self.search_lucene_query(lucene_query=kwargs["dsl_query"])

        def search_esql_query(self, **kwargs):
            return self.search_lucene_query(lucene_query=kwargs["esql_query"])

    fake = Fake()
    assert tools_siem.search_lucene_query("a:b", client=fake)["success"] is True
    assert tools_siem.search_eql_query("process where true", client=fake)["success"] is True
    assert tools_siem.search_dsl_query('{"query":{"match_all":{}}}', client=fake)["success"] is True
    assert tools_siem.search_esql_query("FROM logs-*", client=fake)["success"] is True
