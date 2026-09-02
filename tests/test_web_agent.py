"""Standalone chat UI and agent — no Oracle, no live LLM."""

from __future__ import annotations

from oracle_mcp.agent import ChatAgent, compact_tool_result, tools_for
from oracle_mcp.webapp import create_app


class ScriptedLlm:
    def __init__(self, replies: list[dict]) -> None:
        self.replies = list(replies)

    def complete(self, messages, tools):
        assert tools, "the agent must send tool specs"
        return self.replies.pop(0)


def test_compare_tool_is_only_advertised_when_both_databases_are_served(service):
    names = {t["function"]["name"] for t in tools_for(service)}
    assert "compare_onprem_and_atp_data" in names
    service.settings = service.settings.model_copy(update={"profile": "onprem"})
    names = {t["function"]["name"] for t in tools_for(service)}
    assert "compare_onprem_and_atp_data" not in names


def test_unknown_tool_is_refused_without_touching_the_database(service):
    agent = ChatAgent(service, llm=None)
    result = agent.invoke_tool("drop_table", {})
    assert result["error_code"] == "UNKNOWN_TOOL"


def test_user_role_argument_is_stripped_before_dispatch(service):
    agent = ChatAgent(service, llm=None)
    result = agent.invoke_tool("list_databases", {"user_role": "admin"})
    assert result["status"] == "OK"
    names = {d["database_name"] for d in result["databases"]}
    assert names == {"ONPREM", "ATP"}


def test_agent_runs_a_tool_then_answers(service):
    llm = ScriptedLlm(
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "1",
                        "function": {"name": "list_databases", "arguments": "{}"},
                    }
                ],
            },
            {
                "role": "assistant",
                "content": "Answer:\nOn-Prem and ATP are available.\n\nData Source Used:\n- list_databases",
            },
        ]
    )
    agent = ChatAgent(service, llm)
    result = agent.run("which databases can you query?")
    assert "On-Prem" in result["answer"]
    assert result["tools"][0]["name"] == "list_databases"


def test_compact_tool_result_truncates_large_payloads():
    blob = compact_tool_result({"rows": ["x" * 20_000]})
    assert "truncated" in blob
    assert len(blob) < 13_000


def test_health_and_chat_endpoints(service):
    from fastapi.testclient import TestClient

    llm = ScriptedLlm(
        [{"role": "assistant", "content": "Hello from the test double."}]
    )
    app = create_app(service.settings, service=service, agent=ChatAgent(service, llm))
    client = TestClient(app)
    health = client.get("/api/health").json()
    assert health["ok"] is True
    assert "validate_sql" in health["tools"]
    chat = client.post("/api/chat", json={"question": "hello", "history": []})
    assert chat.status_code == 200
    assert "test double" in chat.json()["answer"]
    page = client.get("/")
    assert page.status_code == 200
    assert b"Oracle data assistant" in page.content
