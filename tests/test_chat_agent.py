"""Standalone chat agent: tool dispatch and identity isolation."""

from __future__ import annotations

from oracle_mcp.agent import ChatAgent, _trim_tool_result
from oracle_mcp.settings import Settings
from oracle_mcp.tools import ToolService


class ScriptedLlm:
    def __init__(self, script: list[dict]) -> None:
        self.script = list(script)

    def complete(self, messages, tools):
        if not self.script:
            return {"role": "assistant", "content": "done"}
        return self.script.pop(0)


def test_chat_agent_exposes_core_tools(service: ToolService, settings: Settings):
    agent = ChatAgent(service, settings, llm=ScriptedLlm([]))
    names = agent.tool_names()
    for needed in (
        "list_databases",
        "list_allowed_schemas",
        "list_allowed_tables",
        "get_table_metadata",
        "search_data_dictionary",
        "validate_sql",
        "execute_readonly_sql",
        "list_active_dq_rules",
        "execute_data_quality_rule",
        "explain_query_result",
        "compare_onprem_and_atp_data",
    ):
        assert needed in names


def test_unknown_tool_is_refused(service: ToolService, settings: Settings):
    agent = ChatAgent(service, settings, llm=ScriptedLlm([]))
    result = agent.dispatch("drop_table", {"table": "x"})
    assert result["error_code"] == "UNKNOWN_TOOL"


def test_model_cannot_pass_a_role_into_dispatch(service: ToolService, settings: Settings):
    """user_role/user_id from the model are stripped before ToolService sees them."""
    agent = ChatAgent(service, settings, llm=ScriptedLlm([]))
    result = agent.dispatch(
        "list_databases",
        {"user_role": "admin", "user_id": "attacker"},
    )
    assert result["status"] == "OK"
    assert "databases" in result


def test_ask_runs_a_tool_then_answers(service: ToolService, settings: Settings):
    llm = ScriptedLlm(
        [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "1",
                        "function": {"name": "list_databases", "arguments": "{}"},
                    }
                ],
            },
            {"role": "assistant", "content": "Answer:\nOn-Prem is available."},
        ]
    )
    agent = ChatAgent(service, settings, llm=llm)
    out = agent.ask("which databases?")
    assert "On-Prem" in out["answer"]
    assert out["tool_trace"][0]["tool"] == "list_databases"
    assert out["tool_trace"][0]["status"] == "OK"


def test_trim_tool_result_keeps_small_payloads():
    small = {"status": "OK", "n": 1}
    assert _trim_tool_result(small) == small


def test_trim_tool_result_caps_large_payloads():
    huge = {"status": "OK", "blob": "x" * 50_000}
    trimmed = _trim_tool_result(huge)
    assert trimmed["truncated"] is True
    assert "preview" in trimmed
