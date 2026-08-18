import asyncio

from src.ai_controller.agent_executor import AgentExecutor, Command, CommandType
from src.llm.base import LLMResult


class _FakeMCP:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": "get_ip_address_report"}]

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments or {}))
        return f"{name}:{(arguments or {}).get('ip')}"


class _Provider:
    def __init__(self):
        self.kwargs = None

    async def complete(self, prompt, **kwargs):
        self.kwargs = {"prompt": prompt, **kwargs}
        return LLMResult(success=True, text="ok", tools_advertised=1, tools_supported=True)

    def cancel(self):
        return None


def _executor(monkeypatch, mcp=None):
    executor = AgentExecutor.__new__(AgentExecutor)
    executor._tool_registry = {}
    executor._active_cluster_id = "cluster-1"
    executor._current_provider = None
    executor._current_process = None
    fake = mcp or _FakeMCP()
    monkeypatch.setattr(executor, "_mcp_client", lambda: fake)
    return executor, fake


def test_run_tool_uses_mcp_when_the_server_has_it(monkeypatch):
    executor, fake = _executor(monkeypatch)
    command = Command(
        raw="run get_ip_address_report on 1.1.1.1",
        command_type=CommandType.RUN_TOOL,
        tool_name="get_ip_address_report",
        arguments={"ip": "1.1.1.1"},
    )

    result = asyncio.run(executor._execute_tool(command))

    assert result.success
    assert result.output == "get_ip_address_report:1.1.1.1"
    assert fake.calls == [("get_ip_address_report", {"ip": "1.1.1.1"})]


def test_freeform_prompt_passes_mcp_client_to_the_llm(monkeypatch):
    executor, fake = _executor(monkeypatch)
    provider = _Provider()
    monkeypatch.setattr("src.llm.registry.get_active_provider", lambda: provider)
    monkeypatch.setattr("src.core.config_storage.get_section", lambda *_args, **_kwargs: {})

    result = asyncio.run(executor._execute_freeform_prompt("enrich 1.1.1.1"))

    assert result.success
    assert provider.kwargs["mcp_client"] is fake
    assert result.output["text"] == "ok"
    assert result.output["tools_supported"] is True
