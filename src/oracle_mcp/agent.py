"""LLM tool loop for the standalone chat UI.

The browser never talks to Oracle. It posts a question here; this module calls
the same ``ToolService`` the MCP server exposes, then asks an OpenAI-compatible
model to narrate. Role and user id are taken from process configuration, not
from the model or the browser.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from .settings import Settings
from .tools import ToolService

logger = logging.getLogger(__name__)

_MAX_TOOL_RESULT_CHARS = 24_000
_MAX_TURNS = 12
_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "system_prompt.md"
_STRIP_ARGS = frozenset({"user_role", "user_id"})


class LlmClient(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]: ...


def load_system_prompt() -> str:
    if _PROMPT_PATH.is_file():
        return _PROMPT_PATH.read_text(encoding="utf-8")
    return (
        "You are a secure enterprise database assistant. Use only the provided "
        "tools. Never invent table names, counts or credentials."
    )


def openai_tool_schemas(*, reconciliation: bool) -> list[dict[str, Any]]:
    """OpenAI function-calling schemas for every ToolService capability."""
    db = {
        "type": "string",
        "description": "Logical database name: ONPREM or ATP.",
    }
    tools: list[dict[str, Any]] = [
        _fn(
            "list_databases",
            "List the Oracle databases this assistant can query, with guardrail limits. "
            "Credentials and hosts are never included.",
            {},
        ),
        _fn(
            "list_allowed_schemas",
            "List schemas this assistant is authorised to read.",
            {"database_name": db},
            required=["database_name"],
        ),
        _fn(
            "list_allowed_tables",
            "List approved tables and views in a schema, with domain and row estimates.",
            {
                "database_name": db,
                "schema_name": {"type": "string", "description": "Schema from list_allowed_schemas."},
            },
            required=["database_name", "schema_name"],
        ),
        _fn(
            "get_table_metadata",
            "Describe an approved table or view: columns, types, sensitivity.",
            {
                "database_name": db,
                "schema_name": {"type": "string"},
                "table_name": {"type": "string"},
            },
            required=["database_name", "schema_name", "table_name"],
        ),
        _fn(
            "search_data_dictionary",
            "Search approved metadata for tables and columns matching a business term. "
            "Call this before writing SQL.",
            {
                "database_name": db,
                "search_text": {"type": "string", "description": "Business term, e.g. customer or serial."},
            },
            required=["database_name", "search_text"],
        ),
        _fn(
            "validate_sql",
            "Validate a SELECT against read-only guardrails. Returns rewritten_safe_sql, "
            "the only text execute_readonly_sql will accept.",
            {
                "database_name": db,
                "sql_text": {"type": "string", "description": "Candidate SELECT statement."},
            },
            required=["database_name", "sql_text"],
        ),
        _fn(
            "execute_readonly_sql",
            "Execute a validated SELECT. Pass exactly rewritten_safe_sql from validate_sql.",
            {
                "database_name": db,
                "validated_sql": {
                    "type": "string",
                    "description": "Exactly rewritten_safe_sql from validate_sql.",
                },
                "bind_parameters": {
                    "type": "object",
                    "description": "Bind variable values.",
                    "additionalProperties": True,
                },
            },
            required=["database_name", "validated_sql"],
        ),
        _fn(
            "list_active_dq_rules",
            "List governed EIM data-quality rules whose RULE_STATUS is ACTIVE, including "
            "DQ_RULE and REFERENCE_CHECKPOINT context.",
            {},
        ),
        _fn(
            "execute_data_quality_rule",
            "Evaluate one ACTIVE EIM DQ rule using two approved aggregate SELECTs. "
            "Returns exact metrics, severity, trend, actions, and a Markdown report.",
            {
                "rule_id": {"type": "string"},
                "target_database": db,
                "total_records_sql": {
                    "type": "string",
                    "description": "Aggregate SELECT returning one integer as TOTAL_RECORDS.",
                },
                "failed_records_sql": {
                    "type": "string",
                    "description": "Aggregate SELECT returning one integer as FAILED_RECORDS.",
                },
            },
            required=[
                "rule_id",
                "target_database",
                "total_records_sql",
                "failed_records_sql",
            ],
        ),
        _fn(
            "explain_query_result",
            "Profile a result set into facts for the business-language answer. "
            "Use these figures verbatim.",
            {
                "user_question": {"type": "string"},
                "sql_text": {"type": "string"},
                "query_result": {
                    "type": "object",
                    "description": "Full envelope returned by execute_readonly_sql.",
                    "additionalProperties": True,
                },
            },
            required=["user_question"],
        ),
    ]
    if reconciliation:
        tools.append(
            _fn(
                "compare_onprem_and_atp_data",
                "Reconcile a business entity between On-Prem and ATP. Both queries are validated first.",
                {
                    "business_entity": {"type": "string"},
                    "matching_key": {
                        "type": "string",
                        "description": "Business key column(s), comma separated.",
                    },
                    "onprem_query": {"type": "string"},
                    "atp_query": {"type": "string"},
                    "compare_columns": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                required=["business_entity", "matching_key", "onprem_query", "atp_query"],
            )
        )
    return tools


def _fn(
    name: str, description: str, properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
                "additionalProperties": False,
            },
        },
    }


class OpenAiCompatibleClient:
    """POST {base}/chat/completions. Works with OpenAI, Azure AI gateway, LiteLLM."""

    def __init__(
        self, *, base_url: str, api_key: str, model: str, timeout_seconds: int
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        url = self.base_url
        if not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions"
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": 0.1,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM unreachable: {exc.reason}") from exc
        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError("LLM returned no choices.")
        return choices[0].get("message") or {}


class ChatAgent:
    def __init__(
        self,
        service: ToolService,
        settings: Settings,
        llm: LlmClient | None = None,
    ) -> None:
        self.service = service
        self.settings = settings
        self.llm = llm or OpenAiCompatibleClient(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key.get_secret_value(),
            model=settings.llm_model,
            timeout_seconds=settings.llm_timeout_seconds,
        )
        self.tools = openai_tool_schemas(
            reconciliation=settings.reconciliation_enabled
        )
        self.system_prompt = load_system_prompt() + self._runtime_preamble()

    def _runtime_preamble(self) -> str:
        dbs = ", ".join(self.service.registry.names) or "(none connected)"
        return (
            "\n\n## Runtime\n"
            f"- Databases available in this process: {dbs}\n"
            f"- Pinned role: {self.settings.pinned_role} "
            "(the user cannot change this)\n"
            f"- Row cap: {self.settings.max_rows}; "
            f"query timeout: {self.settings.query_timeout_seconds}s\n"
            "- Do not call tools with a user_role argument.\n"
        )

    def tool_names(self) -> list[str]:
        return [t["function"]["name"] for t in self.tools]

    def dispatch(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        """Run one tool. Identity args from the model are discarded."""
        args = {k: v for k, v in (arguments or {}).items() if k not in _STRIP_ARGS}
        method = getattr(self.service, name, None)
        if method is None or name not in set(self.tool_names()):
            return {
                "status": "ERROR",
                "error_code": "UNKNOWN_TOOL",
                "message": f"Tool {name!r} is not available on this server.",
            }
        if name in {"execute_readonly_sql", "execute_data_quality_rule"}:
            args.setdefault("user_id", self.settings.pinned_user_id)
        if name == "compare_onprem_and_atp_data":
            args.setdefault("user_id", self.settings.pinned_user_id)
        try:
            result = method(**args)
        except TypeError as exc:
            return {
                "status": "ERROR",
                "error_code": "BAD_ARGUMENTS",
                "message": str(exc),
            }
        except Exception as exc:  # noqa: BLE001 — never leak a stack to the model
            logger.exception("Tool %s failed", name)
            return {
                "status": "ERROR",
                "error_code": "TOOL_FAILED",
                "message": f"{type(exc).__name__}: {exc}",
            }
        return result if isinstance(result, dict) else {"result": result}

    def ask(
        self, question: str, history: list[dict[str, str]] | None = None
    ) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": self.system_prompt}]
        for item in (history or [])[-16:]:
            role = item.get("role")
            content = item.get("content")
            if role in {"user", "assistant"} and isinstance(content, str) and content.strip():
                messages.append({"role": role, "content": content[:8000]})
        messages.append({"role": "user", "content": question[:8000]})

        trace: list[dict[str, Any]] = []
        answer = ""
        for _ in range(_MAX_TURNS):
            message = self.llm.complete(messages, self.tools)
            tool_calls = message.get("tool_calls") or []
            content = (message.get("content") or "").strip()
            if not tool_calls:
                answer = content
                break
            messages.append(message)
            for call in tool_calls:
                fn = (call.get("function") or {})
                name = fn.get("name") or ""
                raw_args = fn.get("arguments") or "{}"
                try:
                    parsed = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except json.JSONDecodeError:
                    parsed = {}
                result = self.dispatch(name, parsed if isinstance(parsed, dict) else {})
                trimmed = _trim_tool_result(result)
                trace.append(
                    {
                        "tool": name,
                        "arguments": {k: v for k, v in parsed.items() if k not in _STRIP_ARGS}
                        if isinstance(parsed, dict)
                        else {},
                        "status": trimmed.get("status") if isinstance(trimmed, dict) else "OK",
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id") or name,
                        "content": json.dumps(trimmed, default=str),
                    }
                )
        else:
            answer = (
                "I reached the tool-call limit before finishing. Narrow the question "
                "or name the schema and table."
            )
        return {
            "answer": answer,
            "tool_trace": trace,
            "role": self.settings.pinned_role,
        }


def _trim_tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(payload, default=str)
    if len(text) <= _MAX_TOOL_RESULT_CHARS:
        return payload
    return {
        "status": payload.get("status", "OK"),
        "truncated": True,
        "note": (
            f"Tool result was {len(text)} characters and was truncated. "
            "Ask for a specific schema, table or filter rather than listing everything."
        ),
        "preview": text[:_MAX_TOOL_RESULT_CHARS],
    }
