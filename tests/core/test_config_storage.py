"""Raw config section helpers preserve unknown keys."""

import json

from src.core.config_storage import load_raw_config, save_raw_config, update_raw_section


def test_update_raw_section_preserves_other_keys(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "thehive": {"base_url": "https://thehive.example", "api_key": "k"},
                "cti_opencti": {"cti_type": "opencti", "base_url": "https://opencti.example"},
            }
        )
    )
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))
    update_raw_section(
        "llm",
        {"provider": "openai"},
        config_path=str(config_path),
    )
    data = load_raw_config(str(config_path))
    assert data["llm"]["provider"] == "openai"
    assert data["cti_opencti"]["base_url"] == "https://opencti.example"
    assert data["thehive"]["api_key"] == "k"
