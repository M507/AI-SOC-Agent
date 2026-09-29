"""web.password is stored as an Argon2id hash."""

import json

import pytest

from src.ai_controller.web.auth import (
    hash_password,
    is_password_hash,
    load_web_auth_config,
    password_matches,
)


def test_hash_password_hides_the_secret_and_verifies():
    stored = hash_password("choose-a-strong-password")
    again = hash_password("choose-a-strong-password")
    assert stored.startswith("$argon2id$")
    assert stored != again
    assert "choose-a-strong-password" not in stored
    assert "m=19456" in stored
    assert "t=2" in stored
    assert "p=1" in stored
    assert password_matches("choose-a-strong-password", stored)
    assert not password_matches("another-password", stored)
    assert not password_matches(stored, stored)


def test_sign_in_rejects_a_stored_plaintext_password():
    from src.ai_controller.web import auth as auth_mod

    cfg = auth_mod.WebAuthConfig(
        username="admin",
        password="choose-a-strong-password",
        session_secret="test-session-secret-value-minimum-32-chars-long",
        session_ttl_seconds=43200,
        cookie_secure=True,
    )
    assert cfg.password == "choose-a-strong-password"
    assert not is_password_hash(cfg.password)
    previous = auth_mod._auth
    auth_mod._auth = auth_mod.SessionManagerAuth(cfg)
    try:
        assert not auth_mod.verify_credentials("admin", "choose-a-strong-password")
    finally:
        auth_mod._auth = previous


def test_plaintext_and_other_hashes_do_not_match():
    secret = "choose-a-strong-password"
    assert not password_matches(secret, secret)
    assert not password_matches(secret, "")
    assert not is_password_hash(secret)
    assert not password_matches(secret, "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert not password_matches(secret, "$argon2d$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_plaintext_password_is_rejected_and_left_unchanged(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    original = {
        "web": {
            "username": "admin",
            "password": "choose-a-strong-password",
            "session_secret": "test-session-secret-value-minimum-32-chars-long",
            "session_ttl_seconds": 43200,
        }
    }
    config_path.write_text(json.dumps(original))
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))

    with pytest.raises(RuntimeError, match="Argon2id"):
        load_web_auth_config(cookie_secure=True)
    assert json.loads(config_path.read_text()) == original


def test_stored_hash_loads_unchanged(tmp_path, monkeypatch):
    stored = hash_password("choose-a-strong-password")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "web": {
                    "username": "admin",
                    "password": stored,
                    "session_secret": "test-session-secret-value-minimum-32-chars-long",
                    "session_ttl_seconds": 43200,
                }
            }
        )
    )
    monkeypatch.setattr("src.core.config_storage.CONFIG_FILE", str(config_path))

    loaded = load_web_auth_config(cookie_secure=True)
    assert loaded.password == stored
    assert json.loads(config_path.read_text())["web"]["password"] == stored
    assert password_matches("choose-a-strong-password", loaded.password)
