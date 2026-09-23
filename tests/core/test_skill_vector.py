"""MCP Skill Vector (MSV) parse/encode and allowment."""

from src.core.skill_vector import (
    DEFAULT_SKILL_VECTOR,
    allowed_tool_names,
    canonicalize,
    is_skill_allowed,
    parse_skill_vector,
)


def test_default_round_trip():
    parsed = parse_skill_vector("")
    assert parsed.encode() == DEFAULT_SKILL_VECTOR
    assert canonicalize(DEFAULT_SKILL_VECTOR) == DEFAULT_SKILL_VECTOR


def test_disable_iris_keeps_thehive_case_tools():
    vector = "MSV:1/IRIS:N/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y"
    assert is_skill_allowed("create_case", vector)
    assert is_skill_allowed("get_recent_alerts", vector)


def test_disable_both_case_solutions():
    vector = canonicalize("MSV:1/CASE:N")
    assert "IRIS:N" in vector
    assert "TH:N" in vector
    assert not is_skill_allowed("create_case", vector)
    assert is_skill_allowed("get_recent_alerts", vector)


def test_skill_override_disables_one_tool():
    vector = DEFAULT_SKILL_VECTOR + "/SK:create_case=N"
    assert not is_skill_allowed("create_case", vector)
    assert is_skill_allowed("list_cases", vector)


def test_skill_override_enables_when_solution_off():
    vector = "MSV:1/IRIS:N/TH:N/SIEM:N/EDR:N/CTI:N/KB:N/ENG:N/RB:N/AG:N/RU:N/SK:get_recent_alerts=Y"
    assert is_skill_allowed("get_recent_alerts", vector)
    assert not is_skill_allowed("search_kql_query", vector)
    assert not is_skill_allowed("create_case", vector)


def test_unknown_tools_remain_allowed():
    names = allowed_tool_names(["create_case", "brand_new_tool"], "MSV:1/CASE:N")
    assert "create_case" not in names
    assert "brand_new_tool" in names


def test_invalid_vector_rejected():
    try:
        canonicalize("MSV:1/NOPE:Y", strict=True)
        assert False, "expected ValueError"
    except ValueError:
        pass
