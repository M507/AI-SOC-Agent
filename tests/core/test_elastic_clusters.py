"""Elastic cluster registry: legacy config shape and public payload."""

from src.core.elastic_clusters import (
    normalize_elastic_section,
    public_clusters,
    registry_from_section,
    upsert_cluster,
)
from src.core.secrets import mask_mapping, merge_secrets


def test_legacy_elastic_becomes_cluster_list():
    section = normalize_elastic_section(
        {
            "base_url": "https://elastic.example:9200",
            "api_key": "secret-api-key-value",
            "verify_ssl": False,
        }
    )
    assert section["default_cluster_id"]
    assert len(section["clusters"]) == 1
    assert section["clusters"][0]["base_url"] == "https://elastic.example:9200"
    assert section["base_url"] == "https://elastic.example:9200"
    assert section["api_key"] == "secret-api-key-value"


def test_multi_cluster_default_and_lookup():
    registry = registry_from_section(
        {
            "default_cluster_id": "prod",
            "clusters": [
                {"id": "lab", "name": "Lab", "base_url": "https://lab:9200", "api_key": "lab-key-value"},
                {"id": "prod", "name": "Prod", "base_url": "https://prod:9200", "api_key": "prod-key-value"},
            ],
        }
    )
    assert registry.default().id == "prod"
    assert registry.get("lab").name == "Lab"
    assert registry.get(None).id == "prod"


def test_upsert_requires_url_and_auth():
    try:
        upsert_cluster({"name": "x", "base_url": ""})
        assert False, "expected ValueError"
    except ValueError:
        pass
    try:
        upsert_cluster({"name": "x", "base_url": "https://elastic.example:9200"})
        assert False, "expected ValueError"
    except ValueError:
        pass
    cluster = upsert_cluster(
        {
            "name": "Lab",
            "base_url": "https://elastic.example:9200/",
            "api_key": "encoded-api-key-value",
            "verify_ssl": False,
        }
    )
    assert cluster.base_url == "https://elastic.example:9200"
    assert cluster.auth_type() == "api_key"
    assert cluster.skill_vector.startswith("MSV:1/")


def test_upsert_keeps_verify_ssl_false_when_omitted():
    existing = upsert_cluster(
        {
            "id": "lab-es",
            "name": "Lab Elasticsearch",
            "base_url": "https://elastic.example:9200",
            "api_key": "encoded-api-key-value",
            "verify_ssl": False,
        }
    )
    updated = upsert_cluster({"id": "lab-es", "base_url": "https://elastic.example:9200"}, existing)
    assert updated.verify_ssl is False


def test_probe_failure_message_ssl():
    from src.core.elastic_clusters import _probe_failure_message

    message = _probe_failure_message(
        "https://10.10.10.88:9200",
        ["elasticsearch: certificate verify failed: self signed certificate"],
        verify_ssl=True,
    )
    assert "TLS verification failed" in message
    assert "Verify TLS" in message


def test_mask_mapping_masks_cluster_list_secrets():
    masked = mask_mapping(
        {
            "clusters": [
                {"id": "lab", "api_key": "super-secret-api-key", "base_url": "https://lab"}
            ]
        }
    )
    assert masked["clusters"][0]["base_url"] == "https://lab"
    assert masked["clusters"][0]["api_key"] != "super-secret-api-key"
    assert "..." in masked["clusters"][0]["api_key"]


def test_merge_secrets_keeps_cluster_api_key_when_masked():
    existing = {
        "clusters": [{"id": "lab", "api_key": "real-secret-api-key", "base_url": "https://lab"}]
    }
    incoming = {
        "clusters": [{"id": "lab", "api_key": "real...-key", "base_url": "https://lab2"}]
    }
    merged = merge_secrets(incoming, existing)
    assert merged["clusters"][0]["api_key"] == "real-secret-api-key"
    assert merged["clusters"][0]["base_url"] == "https://lab2"


def test_public_clusters_masks_secrets(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"elastic": {"default_cluster_id": "lab", "clusters": ['
        '{"id": "lab", "name": "Lab", "base_url": "https://lab:9200",'
        ' "api_key": "super-secret-api-key"}]}}'
    )
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    payload = public_clusters()
    assert payload["default_cluster_id"] == "lab"
    assert payload["clusters"][0]["name"] == "Lab"
    assert payload["clusters"][0]["api_key"] != "super-secret-api-key"
    assert "super-secret-api-key" not in str(payload)
    assert payload["clusters"][0]["skill_vector"].startswith("MSV:1/")
    assert payload["default_skill_vector"].startswith("MSV:1/")
