"""LLM provider registry tests."""

from src.llm.openai_compatible import mcp_tools_to_openai
from src.llm.registry import PROVIDER_CATALOG, create_provider


def test_catalog_includes_expected_providers():
    ids = {item["id"] for item in PROVIDER_CATALOG}
    assert ids == {"cursor_agent", "openai", "openrouter", "openwebui", "custom"}


def test_create_cursor_provider():
    provider = create_provider("cursor_agent", {})
    assert provider.provider_id == "cursor_agent"
    assert provider.display_name == "Cursor Agent"


def test_create_openai_compatible_providers():
    openai = create_provider("openai", {"model": "gpt-4o", "api_key": "sk-test"})
    assert openai.provider_id == "openai"
    assert openai._model() == "gpt-4o"
    assert openai._chat_url() == "https://api.openai.com/v1/chat/completions"

    openrouter = create_provider("openrouter", {"model": "anthropic/claude-sonnet-4"})
    assert "openrouter.ai" in openrouter._chat_url()

    openwebui = create_provider("openwebui", {"base_url": "http://10.10.10.82:8080/", "model": "llama3"})
    assert openwebui._chat_url() == "http://10.10.10.82:8080/api/v1/chat/completions"


def test_mcp_tools_to_openai():
    converted = mcp_tools_to_openai(
        [
            {
                "name": "list_cases",
                "description": "List cases",
                "inputSchema": {"type": "object", "properties": {"status": {"type": "string"}}},
            }
        ]
    )
    assert converted[0]["type"] == "function"
    assert converted[0]["function"]["name"] == "list_cases"
    assert "status" in converted[0]["function"]["parameters"]["properties"]
