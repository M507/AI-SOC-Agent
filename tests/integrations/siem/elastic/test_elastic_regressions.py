import warnings
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from urllib3.exceptions import InsecureRequestWarning

from src.core.errors import IntegrationError
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.integrations.siem.elastic.elastic_http import ElasticHttpClient


def _response(status_code=200, body=None):
    return SimpleNamespace(
        status_code=status_code,
        text="",
        reason="Not Found",
        json=lambda: body if body is not None else {},
    )


def test_structured_elastic_error_keeps_http_status_for_index_fallback():
    client = ElasticHttpClient("https://elastic.example")
    response = _response(
        404,
        {"error": {"type": "index_not_found_exception", "reason": "no such index"}},
    )

    with pytest.raises(IntegrationError, match=r"HTTP 404.*index_not_found_exception"):
        client._handle_elastic_error(response)


def test_kibana_style_error_is_reported_without_parser_failure():
    client = ElasticHttpClient("https://kibana.example")
    response = _response(
        404,
        {"statusCode": 404, "error": "Not Found", "message": "Not Found"},
    )

    with pytest.raises(IntegrationError, match=r"HTTP 404: Not Found"):
        client._handle_elastic_error(response)


def test_explicit_disabled_tls_verification_does_not_flood_logs(monkeypatch):
    def fake_request(**kwargs):
        warnings.warn("unverified", InsecureRequestWarning)
        return _response(200, {"ok": True})

    monkeypatch.setattr("requests.request", fake_request)
    client = ElasticHttpClient("https://elastic.example", verify_ssl=False)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert client.get("") == {"ok": True}

    assert not [item for item in caught if item.category is InsecureRequestWarning]


def test_empty_json_search_becomes_bounded_match_all_query():
    http = Mock()
    http.post.return_value = {"hits": {"hits": [], "total": {"value": 0}}}
    client = ElasticSIEMClient(http)

    result = client.search_security_events("{}", limit=7)

    assert result.total_count == 0
    assert http.post.call_args.kwargs["json_data"] == {
        "query": {"match_all": {}},
        "size": 7,
    }
