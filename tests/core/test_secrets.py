"""Tests for secret masking helpers used by the settings APIs."""

from src.core.secrets import is_masked_secret, mask_mapping, mask_secret, merge_secrets


def test_mask_secret_short_values():
    assert mask_secret("") == ""
    assert mask_secret("short") == "••••••••"


def test_mask_secret_long_values():
    assert mask_secret("sk-abcdefghijklmnopqrstuvwxyz") == "sk-a...wxyz"


def test_is_masked_secret():
    assert is_masked_secret("")
    assert is_masked_secret("sk-a...wxyz")
    assert is_masked_secret("••••••••")
    assert not is_masked_secret("sk-live-real-key-value")


def test_merge_secrets_keeps_existing_when_masked():
    existing = {"api_key": "sk-real-secret-value", "model": "gpt-4o"}
    incoming = {"api_key": "sk-r...alue", "model": "gpt-4.1"}
    merged = merge_secrets(incoming, existing)
    assert merged["api_key"] == "sk-real-secret-value"
    assert merged["model"] == "gpt-4.1"


def test_mask_mapping_nested():
    masked = mask_mapping({"openai": {"api_key": "sk-abcdefghijklmnopqrstuvwxyz", "model": "gpt-4o"}})
    assert masked["openai"]["model"] == "gpt-4o"
    assert masked["openai"]["api_key"] != "sk-abcdefghijklmnopqrstuvwxyz"
    assert "..." in masked["openai"]["api_key"]
