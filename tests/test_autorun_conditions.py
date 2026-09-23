import json

from src.ai_controller.autorun_conditions import (
    DEFAULT_ALERT_LIMIT,
    MAX_CONTEXT_CHARS,
    build_condition_context,
    parse_condition_spec,
)


def test_bare_condition_keeps_default_limits():
    spec = parse_condition_spec("get_recent_alerts")

    assert spec.name == "get_recent_alerts"
    assert spec.limit is None
    assert spec.alert_limit() == DEFAULT_ALERT_LIMIT


def test_trailing_integer_sets_the_limit():
    spec = parse_condition_spec("get_recent_alerts 1")

    assert spec.name == "get_recent_alerts"
    assert spec.limit == 1
    assert spec.alert_limit() == 1


def test_limit_keyword_and_run_prefix_are_accepted():
    assert parse_condition_spec("run get_recent_alerts limit=5").limit == 5
    assert parse_condition_spec("run get_recent_alerts").name == "get_recent_alerts"


def test_non_numeric_suffix_is_left_for_the_generic_executor():
    spec = parse_condition_spec("run some_tool with hours_back=2")

    assert spec.limit is None
    assert spec.name == "some_tool with hours_back=2"


def test_context_carries_the_alert_so_the_agent_need_not_ask():
    output = {
        "uninvestigated_alerts": 1,
        "suggested_alert_to_triage": {"id": "abc123", "title": "Suspicious PowerShell"},
    }

    context = build_condition_context(parse_condition_spec("get_recent_alerts 1"), output)

    assert "abc123" in context
    assert "Suspicious PowerShell" in context
    assert "get_recent_alerts" in context


def test_empty_condition_output_produces_no_context():
    spec = parse_condition_spec("get_recent_alerts")

    assert build_condition_context(spec, None) is None
    assert build_condition_context(spec, {}) is None


def test_large_output_is_summarized_to_protect_the_prompt():
    output = {
        "total_alerts": 500,
        "uninvestigated_alerts": 500,
        "group_count": 2,
        "suggested_alert_to_triage": {"id": "keep-me"},
        "groups": [
            {
                "group_id": f"alert_group_{index}",
                "title": "Noisy rule",
                "count": 3,
                "example_alerts": [{"id": f"drop-{index}", "blob": "x" * 400}],
            }
            for index in range(60)
        ],
    }

    context = build_condition_context(parse_condition_spec("get_recent_alerts"), output)

    assert len(context) <= MAX_CONTEXT_CHARS + 200
    assert "keep-me" in context
    assert "drop-0" not in context


def test_context_is_valid_json_the_model_can_parse():
    output = {"cases": [{"id": 7, "title": "Case"}], "count": 1}

    context = build_condition_context(parse_condition_spec("list_cases"), output)
    payload = context.split("```json", 1)[1].rsplit("```", 1)[0]

    assert json.loads(payload) == output
