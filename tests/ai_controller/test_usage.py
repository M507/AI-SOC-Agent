"""Token ledger, usage parsing, and price math."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.ai_controller.usage import (
    append_usage,
    cost_for_tokens,
    dashboard,
    format_cost,
    parse_usage_payload,
    price_tokens,
    pricing_path,
    record_model_round,
    usage_footer,
    usage_path,
)


def _usage_dir(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "servee"
    monkeypatch.setenv("SAMIGPT_USAGE_DIR", str(root))
    return root


def test_parse_openai_chat_usage():
    parsed = parse_usage_payload(
        {
            "model": "gpt-5.4",
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 80,
                "prompt_tokens_details": {"cached_tokens": 200},
            },
        }
    )
    assert parsed["usage_reported"] is True
    assert parsed["reported_model"] == "gpt-5.4"
    assert parsed["input_tokens"] == 1000
    assert parsed["cached_input_tokens"] == 200
    assert parsed["output_tokens"] == 80
    assert parsed["cache_write_tokens"] == 0


def test_parse_openwebui_responses_usage():
    parsed = parse_usage_payload(
        {
            "type": "response.completed",
            "response": {
                "model": "auto",
                "usage": {
                    "input_tokens": 4534,
                    "output_tokens": 812,
                    "input_tokens_details": {
                        "cached_tokens": 120,
                        "cache_write_tokens": 40,
                    },
                },
            },
        }
    )
    assert parsed["usage_reported"] is True
    assert parsed["reported_model"] == "auto"
    assert parsed["input_tokens"] == 4534
    assert parsed["cached_input_tokens"] == 120
    assert parsed["cache_write_tokens"] == 40
    assert parsed["output_tokens"] == 812


def test_parse_omitted_usage_is_unreported():
    parsed = parse_usage_payload({"choices": [{"message": {"content": "hi"}}]})
    assert parsed["usage_reported"] is False
    assert parsed["input_tokens"] == 0
    assert parsed["output_tokens"] == 0


def test_cached_input_is_a_subset_of_input():
    tokens = {
        "usage_reported": True,
        "input_tokens": 1000,
        "cached_input_tokens": 200,
        "cache_write_tokens": 50,
        "output_tokens": 100,
    }
    rates = {"input": 2.0, "cache_read": 0.5, "cache_write": 3.0, "output": 10.0}
    # uncached 800, cached 200, write 50, out 100
    assert cost_for_tokens(tokens, rates) == 0.00285


def test_unreported_usage_has_no_dollar_amount():
    tokens = {
        "usage_reported": False,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 0,
    }
    rates = {"input": 2.5, "cache_read": 0.35, "cache_write": 2.5, "output": 10.0}
    assert cost_for_tokens(tokens, rates) is None
    assert usage_footer(tokens, {"priced": False, "pricing_ok": True}) == "Tokens: usage not reported"


def test_append_manual_and_autorun_rows(tmp_path, monkeypatch):
    _usage_dir(tmp_path, monkeypatch)
    manual = record_model_round(
        tokens={
            "usage_reported": True,
            "reported_model": "gpt-5.4",
            "input_tokens": 100,
            "cached_input_tokens": 10,
            "cache_write_tokens": 0,
            "output_tokens": 20,
        },
        provider="openwebui",
        configured_model="auto",
        session_id="sess-1",
        entry_id="entry-1",
        session_type="manual",
        session_name="Night shift",
        command="investigate this alert",
    )
    autorun = record_model_round(
        tokens={
            "usage_reported": True,
            "reported_model": "auto",
            "input_tokens": 50,
            "cached_input_tokens": 0,
            "cache_write_tokens": 0,
            "output_tokens": 8,
        },
        provider="openwebui",
        configured_model="auto",
        session_id="sess-auto",
        entry_id="entry-2",
        session_type="autorun",
        session_name="Autorun: widget abuse",
        autorun_id="auto-1",
        autorun_name="widget abuse",
        command="run triage",
    )
    assert manual is not None
    assert autorun is not None
    data = dashboard()
    assert data["success"] is True
    assert data["total_calls"] == 2
    types = {row["session_type"] for row in data["calls"]}
    names = {row["session_name"] for row in data["sessions"]}
    assert types == {"manual", "autorun"}
    assert "Night shift" in names
    assert "Autorun: widget abuse" in names
    assert any(row.get("autorun_name") == "widget abuse" for row in data["sessions"])


def test_missing_price_keeps_tokens_without_dollars(tmp_path, monkeypatch):
    root = _usage_dir(tmp_path, monkeypatch)
    root.mkdir(parents=True)
    (root / "pricing.json").write_text(
        json.dumps({"currency": "USD", "unit": "per_million_tokens", "models": {}}),
        encoding="utf-8",
    )
    record_model_round(
        tokens={
            "usage_reported": True,
            "reported_model": "mystery-model",
            "input_tokens": 40,
            "cached_input_tokens": 0,
            "cache_write_tokens": 0,
            "output_tokens": 12,
        },
        provider="openwebui",
        configured_model="mystery-model",
        session_id="sess-2",
        session_type="manual",
        session_name="Unpriced",
    )
    priced = price_tokens(
        {
            "usage_reported": True,
            "input_tokens": 40,
            "cached_input_tokens": 0,
            "cache_write_tokens": 0,
            "output_tokens": 12,
        },
        "mystery-model",
    )
    assert priced["priced"] is False
    assert priced["cost_usd"] is None
    data = dashboard()
    row = data["calls"][0]
    assert row["input_tokens"] == 40
    assert row["output_tokens"] == 12
    assert row["priced"] is False
    assert row["cost_usd"] is None
    assert data["unpriced_calls"] == 1
    footer = usage_footer(row, priced)
    assert "unpriced" in footer
    assert "40" in footer


def test_overlapping_appends_write_intact_lines(tmp_path, monkeypatch):
    _usage_dir(tmp_path, monkeypatch)

    def write(index: int):
        return append_usage(
            {
                "session_id": f"s-{index}",
                "session_name": f"Session {index}",
                "session_type": "autorun",
                "input_tokens": index,
                "output_tokens": 1,
                "usage_reported": True,
            }
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(write, range(20)))
    assert all(row is not None for row in rows)
    data = dashboard()
    assert data["total_calls"] == 20
    ids = {row["session_id"] for row in data["calls"]}
    assert len(ids) == 20


def test_format_cost_does_not_round_small_spend_to_zero():
    assert format_cost(0.021) == "$0.021"
    assert format_cost(0.0004) == "$0.0004"
    assert format_cost(1.5) == "$1.50"


def test_unknown_reported_model_uses_configured_auto_rates(tmp_path, monkeypatch):
    root = _usage_dir(tmp_path, monkeypatch)
    root.mkdir(parents=True)
    (root / "pricing.json").write_text(
        json.dumps(
            {
                "currency": "USD",
                "unit": "per_million_tokens",
                "models": {
                    "auto": {"input": 2.5, "cache_write": 2.5, "cache_read": 0.35, "output": 10.0},
                },
            }
        ),
        encoding="utf-8",
    )
    priced = price_tokens(
        {
            "usage_reported": True,
            "input_tokens": 1_000_000,
            "cached_input_tokens": 0,
            "cache_write_tokens": 0,
            "output_tokens": 0,
        },
        "some-routed-name",
        "auto",
    )
    assert priced["priced"] is True
    assert priced["model_key"] == "auto"
    assert priced["cost_usd"] == 2.5


def test_ledger_lives_outside_the_install_tree(monkeypatch):
    monkeypatch.delenv("SAMIGPT_USAGE_DIR", raising=False)
    repo = Path(__file__).resolve().parents[2]
    unit = (repo / "servee" / "servee.service").read_text(encoding="utf-8")
    installer = (repo / "servee" / "install.sh").read_text(encoding="utf-8")
    assert "ReadWritePaths=/opt/servee /var/lib/servee" in unit
    assert "rm -rf \"${INSTALL_DIR}\"" in installer
    assert "/var/lib/servee" not in installer
    assert str(usage_path()) == "/var/lib/servee/usage.jsonl"
    assert str(pricing_path()) == "/var/lib/servee/pricing.json"
