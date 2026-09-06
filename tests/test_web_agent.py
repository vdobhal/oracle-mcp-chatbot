"""Standalone chat UI and agent — no Oracle, no live LLM."""

from __future__ import annotations

import httpx
from oracle_mcp.agent import ChatAgent, compact_tool_result, tools_for
from oracle_mcp.collibra import CollibraClient
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
    blob = compact_tool_result({"rows": ["x" * 30_000]})
    assert "truncated" in blob
    assert len(blob) < 21_000


def test_collibra_tools_advertised_when_client_configured(service):
    collibra = CollibraClient(url="https://example.com/mcp", api_key="secret-token")
    tools = tools_for(service, collibra=collibra)
    names = {t["function"]["name"] for t in tools}
    assert "search_asset_keyword" in names
    assert "get_asset_details" in names
    assert "validate_sql" in names


def test_collibra_tool_without_configured_client_returns_helpful_error(service):
    agent = ChatAgent(service, llm=None, collibra=None)
    result = agent.invoke_tool("search_asset_keyword", {"query": "customer"})
    assert result["status"] == "ERROR"
    assert result["error_code"] == "COLLIBRA_NOT_CONFIGURED"


def test_collibra_client_invoke_mcp_jsonrpc(monkeypatch):
    def fake_post(url, headers, json, timeout):
        assert headers.get("Authorization") == "Bearer fake-token"
        assert json["method"] == "tools/call"
        assert json["params"]["name"] == "search_asset_keyword"
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": '{"results": [{"name": "Serial Number", "id": "123"}], "total": 1}',
                        }
                    ]
                },
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = CollibraClient(url="https://example.com/mcp", api_key="fake-token")
    result = client.invoke_tool("search_asset_keyword", {"query": "Serial Number"})
    assert "results" in result
    assert result["results"][0]["name"] == "Serial Number"


def test_collibra_client_handles_sse_event_stream(monkeypatch):
    sse_body = (
        "event: message\r\n"
        'data: {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\\"results\\": [{\\"name\\": \\"IB Attributes/Enrichments\\", \\"id\\": \\"uuid-999\\"}], \\"total\\": 1}"}]}}\r\n\r\n'
    )

    def fake_post(url, headers, json, timeout):
        return httpx.Response(
            200,
            text=sse_body,
            headers={"Content-Type": "text/event-stream"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = CollibraClient(url="https://example.com/mcp", api_key="fake-token")
    result = client.invoke_tool("search_asset_keyword", {"query": "IB Attributes"})
    assert "results" in result
    assert result["results"][0]["name"] == "IB Attributes/Enrichments"
    assert result["results"][0]["id"] == "uuid-999"


def test_collibra_client_handles_multi_line_sse_stream(monkeypatch):
    sse_body = (
        "event: message\n"
        'data: {"jsonrpc": "2.0", "method": "notifications/progress"}\n\n'
        "event: message\n"
        'data: {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\\"found\\": true, \\"name\\": \\"Serial Number\\"}"}]}}\n\n'
    )

    def fake_post(url, headers, json, timeout):
        return httpx.Response(
            200,
            text=sse_body,
            headers={"Content-Type": "text/event-stream"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = CollibraClient(url="https://example.com/mcp", api_key="fake-token")
    result = client.invoke_tool("get_asset_details", {"assetId": "123"})
    assert result.get("found") is True
    assert result.get("name") == "Serial Number"


def test_collibra_client_handles_403_scope_error(monkeypatch):
    def fake_post(url, headers, json, timeout):
        return httpx.Response(
            403,
            text='{"message": "Missing required scopes: dgc.ai-copilot"}',
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = CollibraClient(url="https://example.com/mcp", api_key="fake-token")
    result = client.invoke_tool("discover_business_glossary", {"query": "customer"})
    assert result["status"] == "ERROR"
    assert result["error_code"] == "FORBIDDEN"
    assert "dgc.ai-copilot" in result["message"]


def test_agent_runs_collibra_tool_then_answers(service, monkeypatch):
    def fake_post(url, headers, json, timeout):
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": '{"results": [{"name": "IB Attributes/Enrichments", "id": "uuid-123"}], "total": 1}',
                        }
                    ]
                },
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    collibra = CollibraClient(url="https://example.com/mcp", api_key="fake-token")
    llm = ScriptedLlm(
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "1",
                        "function": {
                            "name": "search_asset_keyword",
                            "arguments": '{"query": "IB Attributes/Enrichments"}',
                        },
                    }
                ],
            },
            {
                "role": "assistant",
                "content": "Answer:\nFound IB Attributes/Enrichments in Collibra.\n\nData Source Used:\n- Collibra",
            },
        ]
    )
    agent = ChatAgent(service, llm, collibra=collibra)
    result = agent.run("Find IB Attributes/Enrichments in Collibra")
    assert "Found IB Attributes/Enrichments in Collibra" in result["answer"]
    assert result["tools"][0]["name"] == "search_asset_keyword"
    assert "Found 1 asset(s)" in result["tools"][0]["summary"]


def test_health_and_chat_endpoints(service):
    from fastapi.testclient import TestClient

    llm = ScriptedLlm(
        [{"role": "assistant", "content": "Hello from the test double."}]
    )
    collibra = CollibraClient(url="https://example.com/mcp", api_key="token")
    app = create_app(
        service.settings,
        service=service,
        agent=ChatAgent(service, llm, collibra=collibra),
    )
    client = TestClient(app)
    health = client.get("/api/health").json()
    assert health["ok"] is True
    assert health["collibra_configured"] is True
    assert "validate_sql" in health["tools"]
    assert "search_asset_keyword" in health["tools"]

    session = client.get("/api/session").json()
    assert session["collibra_configured"] is True

    chat = client.post("/api/chat", json={"question": "hello", "history": []})
    assert chat.status_code == 200
    assert "test double" in chat.json()["answer"]
    page = client.get("/")
    assert page.status_code == 200
    assert b"MDM (CDM,IB, Collibra) Data Assistant" in page.content


def test_collibra_parameter_normalization_and_prepare_create_asset(monkeypatch):
    captured_payloads = []

    def fake_post(url, headers=None, json=None, timeout=None):
        captured_payloads.append(json)
        return httpx.Response(
            status_code=200,
            text='event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"status\\":\\"success\\",\\"domainOptions\\":[{\\"id\\":\\"d1\\",\\"name\\":\\"IB Mastering\\"}]}"}]}}\n\n',
        )

    monkeypatch.setattr("httpx.post", fake_post)
    client = CollibraClient(api_key="test-key")

    # Test parameter normalization for get_table_semantics
    client.invoke_tool("get_table_semantics", {"assetId": "uuid-123"})
    assert captured_payloads[-1]["params"]["arguments"]["tableId"] == "uuid-123"

    # Test parameter normalization for discover_business_glossary
    client.invoke_tool("discover_business_glossary", {"query": "test query"})
    assert captured_payloads[-1]["params"]["arguments"]["input"] == "test query"

    # Test prepare_create_asset
    result = client.invoke_tool("prepare_create_asset", {"assetType": "Data Attribute"})
    assert result.get("status") in {"OK", "success"}
    assert "IB Mastering" in str(result)


def test_collibra_search_fallback_when_remote_returns_500(monkeypatch):
    def fake_post_500(url, headers=None, json=None, timeout=None):
        return httpx.Response(
            status_code=200,
            text='event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"HTTP 500: {\\"statusCode\\":500}"}],"isError":true}}\n\n',
        )

    monkeypatch.setattr("httpx.post", fake_post_500)
    client = CollibraClient(api_key="test-key")

    # When search_asset_keyword is called for IB Mastering domain and server returns 500,
    # it must fall back to the catalog assets instead of raising error
    res = client.invoke_tool(
        "search_asset_keyword",
        {"query": "*", "domainFilter": ["81e4cbc9-b20c-446c-8672-2617c153e327"]},
    )
    assert res.get("status") == "success"
    assert res.get("total") == 14
    names = {item["name"] for item in res.get("results", [])}
    assert "Serial Number" in names
    assert "Product Series" in names
    assert "Platform" in names
    assert "EOS Date" in names


