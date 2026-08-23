"""Server wiring tests.

Uses FastMCP's in-memory client, which exercises the real tool registration,
schema generation and dispatch path without a subprocess or a socket. Pools are
created lazily, so no Oracle instance is contacted.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastmcp import Client

from oracle_mcp.policy import clear_policy_cache
from oracle_mcp.server import create_server
from oracle_mcp.settings import Settings

BASE_ENV = {
    "ONPREM_USER": "CHATBOT_RO",
    "ONPREM_PASSWORD": "test-password",
    "ONPREM_HOST": "db.internal",
    "ONPREM_PORT": "1521",
    "ONPREM_SERVICE_NAME": "CDMPRD",
    "ATP_USER": "CHATBOT_RO",
    "ATP_PASSWORD": "test-password",
    "ATP_DSN": "myatp_low",
    "ATP_WALLET_DIR": "/opt/oracle/wallets/atp",
    "ATP_WALLET_PASSWORD": "wallet-password",
}


@pytest.fixture
def env(monkeypatch):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    clear_policy_cache()
    return monkeypatch


def build(env, policy_dir, tmp_path, profile: str) -> Settings:
    return Settings(
        profile=profile,
        transport="stdio",
        policy_dir=policy_dir,
        audit_sink="file",
        audit_file=tmp_path / "audit.jsonl",
        role_binding_mode="env",
        pinned_role="analyst",
    )


async def tool_names(server) -> list[str]:
    async with Client(server) as client:
        return sorted(t.name for t in await client.list_tools())


def test_onprem_server_exposes_the_expected_tools(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "onprem"))
    names = asyncio.run(tool_names(server))
    assert names == [
        "execute_data_quality_rule",
        "execute_readonly_sql",
        "explain_query_result",
        "get_table_metadata",
        "list_active_dq_rules",
        "list_allowed_schemas",
        "list_allowed_tables",
        "list_databases",
        "search_data_dictionary",
        "validate_sql",
    ]
    assert "compare_onprem_and_atp_data" not in names


def test_atp_server_exposes_the_same_tool_surface(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "atp"))
    assert "validate_sql" in asyncio.run(tool_names(server))


def test_reconciliation_tool_appears_only_in_the_both_profile(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "both"))
    assert "compare_onprem_and_atp_data" in asyncio.run(tool_names(server))


def test_tools_carry_descriptions_and_schemas(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "onprem"))

    async def inspect_tools():
        async with Client(server) as client:
            return {t.name: t for t in await client.list_tools()}

    tools = asyncio.run(inspect_tools())
    validate = tools["validate_sql"]
    assert validate.description and "SELECT-only" in validate.description
    assert set(validate.inputSchema["properties"]) >= {"database_name", "sql_text"}


def test_a_tool_call_round_trips_through_the_protocol(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "onprem"))

    async def call():
        async with Client(server) as client:
            return await client.call_tool(
                "validate_sql",
                {
                    "database_name": "ONPREM",
                    "sql_text": "SELECT customer_id FROM CDM_RPT.V_CUSTOMER_MASTER",
                },
            )

    result = asyncio.run(call())
    payload = result.data if hasattr(result, "data") else json.loads(result.content[0].text)
    assert payload["validation_status"] == "APPROVED"
    assert "FETCH FIRST 500 ROWS ONLY" in payload["rewritten_safe_sql"]


def test_rejected_sql_returns_a_structured_error_not_an_exception(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "onprem"))

    async def call():
        async with Client(server) as client:
            return await client.call_tool(
                "validate_sql",
                {
                    "database_name": "ONPREM",
                    "sql_text": "DROP TABLE CDM_RPT.V_CUSTOMER_MASTER",
                },
            )

    result = asyncio.run(call())
    payload = result.data if hasattr(result, "data") else json.loads(result.content[0].text)
    assert payload["validation_status"] == "REJECTED"
    assert payload["validation_errors"]


def test_list_databases_over_the_protocol_hides_credentials(env, policy_dir, tmp_path):
    server = create_server(build(env, policy_dir, tmp_path, "both"))

    async def call():
        async with Client(server) as client:
            return await client.call_tool("list_databases", {})

    result = asyncio.run(call())
    payload = result.data if hasattr(result, "data") else json.loads(result.content[0].text)
    serialised = json.dumps(payload).lower()
    assert "test-password" not in serialised
    assert "wallet-password" not in serialised
    assert "myatp_low" not in serialised
    assert payload["reconciliation_available"] is True
