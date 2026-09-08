"""LLM agent that calls ToolService — the same tools the MCP server exposes.

The chat UI uses this instead of Cursor. Security still lives in ToolService:
the model can only invoke named tools, and validate_sql / execute_readonly_sql
still refuse anything that is not a capped SELECT against approved objects.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx

from .collibra import COLLIBRA_TOOL_NAMES, CollibraClient
from .tools import ToolService

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "system_prompt.md"
_MAX_TOOL_ROUNDS = 12
_MAX_TOOL_RESULT_CHARS = 20_000


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_databases",
            "description": "List Oracle databases this assistant can query, with guardrail limits. Never includes credentials.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_allowed_schemas",
            "description": "List schemas the current role may read on a database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {
                        "type": "string",
                        "description": "ONPREM or ATP",
                    }
                },
                "required": ["database_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_allowed_tables",
            "description": "List approved tables and views in a schema, with domain and row estimates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {"type": "string"},
                    "schema_name": {"type": "string"},
                },
                "required": ["database_name", "schema_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_table_metadata",
            "description": (
                "Describe an approved table or view: every column, with types, "
                "nullability and sensitivity. This is the only complete column "
                "list. Call it before answering any question about what "
                "attributes, columns or fields an object has."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {"type": "string"},
                    "schema_name": {"type": "string"},
                    "table_name": {"type": "string"},
                },
                "required": ["database_name", "schema_name", "table_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_data_dictionary",
            "description": (
                "Find candidate tables and columns matching a business term. "
                "Returns only the columns whose names match the search text, "
                "never an object's full column list, so a search for 'product' "
                "returns the columns spelled PRODUCT and hides the rest. Use it "
                "to locate an object, then call get_table_metadata to list its "
                "columns."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {"type": "string"},
                    "search_text": {"type": "string"},
                },
                "required": ["database_name", "search_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_sql",
            "description": "Validate a SELECT against read-only guardrails. Returns rewritten_safe_sql, the only text execute_readonly_sql will accept.",
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {"type": "string"},
                    "sql_text": {"type": "string"},
                },
                "required": ["database_name", "sql_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_readonly_sql",
            "description": "Execute a previously validated SELECT and return masked, capped rows. Pass exactly rewritten_safe_sql from validate_sql.",
            "parameters": {
                "type": "object",
                "properties": {
                    "database_name": {"type": "string"},
                    "validated_sql": {"type": "string"},
                    "bind_parameters": {"type": "object"},
                },
                "required": ["database_name", "validated_sql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_query_result",
            "description": "Profile a result set into facts for a business-language answer. Use these figures verbatim.",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_question": {"type": "string"},
                    "sql_text": {"type": "string"},
                    "query_result": {"type": "object"},
                    "table_metadata": {"type": "object"},
                },
                "required": ["user_question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_onprem_and_atp_data",
            "description": "Reconcile a business entity between On-Prem and ATP. Both queries are validated before either runs. Only available when both databases are enabled in this process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "business_entity": {"type": "string"},
                    "matching_key": {"type": "string"},
                    "onprem_query": {"type": "string"},
                    "atp_query": {"type": "string"},
                    "compare_columns": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "business_entity",
                    "matching_key",
                    "onprem_query",
                    "atp_query",
                ],
            },
        },
    },
]


# Phrases a model reaches for when it wants the user to pick the dataset for it.
# Matched only on an answer that called no tool at all, which is the shape the
# system prompt forbids: asking which table to use is what the metadata tools
# are for.
_SCOPE_QUESTION_PATTERNS = re.compile(
    r"""
    are\ you\ asking\ about
    | which\ of\ (these|the\ following)
    | reply\ with\ which
    | let\ me\ know\ which
    | (could|can|would)\ you\ (please\ )?(clarify|specify|confirm)
    | please\ (clarify|specify)
    | need\ (you\ to\ )?(narrow|specify|clarify)
    | narrow\ (this|it)\ (down|slightly)
    | which\ (dataset|table|schema|database|domain|system)\b
    | one\ clarification
    | i\ need\ you\ to
    """,
    re.IGNORECASE | re.VERBOSE,
)

_DISCOVERY_NUDGE = (
    "You answered without calling a single tool and asked me to choose the "
    "dataset. Do not do that. The metadata tools exist precisely so you can "
    "resolve this yourself.\n\n"
    "Run the discovery chain now and then answer the original question:\n"
    "1. Query EIM_APPS.EIM_AI_LOOKUP_DETAILS on ONPREM to route the question. "
    "Its COMMENTS column says what each dataset covers and KEY_COLUMNS gives "
    "the keys.\n"
    "2. Confirm the chosen object with get_table_metadata, and use "
    "search_data_dictionary if the catalog does not settle it.\n"
    "3. Answer from the tool results only. Never list column or attribute "
    "names from your own knowledge — the ones you recall are not the ones in "
    "this database.\n\n"
    "If several datasets genuinely qualify, answer for the most likely one, "
    "name that choice under Assumptions, and list the alternatives you set "
    "aside. Ask a question only if discovery has run and still leaves a "
    "choice only I can make."
)


def asks_instead_of_discovering(answer: str) -> bool:
    """Whether a no-tool answer is punting the dataset choice back to the user.

    Rule 10 of the system prompt forbids this, and rule 15 forbids the invented
    column lists that tend to come with it, but both were advisory only. The
    prompt itself says a rule not enforced in code is a gap, so this closes it.
    """
    return bool(answer) and bool(_SCOPE_QUESTION_PATTERNS.search(answer))


def load_system_prompt() -> str:
    if _SYSTEM_PROMPT_PATH.is_file():
        return _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    return (
        "You are a secure enterprise database assistant. Use only the provided "
        "tools. Discover metadata before writing SQL. Call validate_sql before "
        "execute_readonly_sql, and pass rewritten_safe_sql unchanged. Never "
        "guess numbers. Always include Data Source Used."
    )


def tools_for(
    service: ToolService,
    collibra: CollibraClient | None = None,
) -> list[dict[str, Any]]:
    names = {
        "list_databases",
        "list_allowed_schemas",
        "list_allowed_tables",
        "get_table_metadata",
        "search_data_dictionary",
        "validate_sql",
        "execute_readonly_sql",
        "explain_query_result",
    }
    if service.settings.reconciliation_enabled:
        names.add("compare_onprem_and_atp_data")
    specs = [spec for spec in TOOL_SPECS if spec["function"]["name"] in names]
    if collibra is not None:
        specs.extend(collibra.list_tools())
    return specs


def compact_tool_result(payload: Any) -> str:
    if isinstance(payload, dict) and "results" in payload and isinstance(payload["results"], list):
        cleaned_results = []
        for item in payload["results"]:
            if isinstance(item, dict):
                cleaned = {
                    k: v
                    for k, v in item.items()
                    if k not in {"createdBy", "createdOn", "lastModifiedOn"}
                }
                cleaned_results.append(cleaned)
            else:
                cleaned_results.append(item)
        payload = {**payload, "results": cleaned_results}
    text = json.dumps(payload, default=str, ensure_ascii=False)
    if len(text) <= _MAX_TOOL_RESULT_CHARS:
        return text
    return text[: _MAX_TOOL_RESULT_CHARS] + "\n…[truncated for the model; the UI kept the full tool result]"


def summarise_tool_result(name: str, payload: dict[str, Any]) -> str:
    status = payload.get("status") or payload.get("validation_status") or "OK"
    if name == "list_allowed_tables":
        return f"{status}: {len(payload.get('objects') or [])} object(s)"
    if name == "search_data_dictionary":
        return f"{status}: {payload.get('match_count', 0)} match(es)"
    if name == "execute_readonly_sql":
        return f"{status}: {payload.get('row_count', 0)} row(s)"
    if name == "validate_sql":
        return f"{payload.get('validation_status') or status}"
    if name == "list_allowed_schemas":
        return f"{status}: {len(payload.get('schemas') or [])} schema(s)"
    if name == "search_asset_keyword":
        results = payload.get("results")
        if isinstance(results, list):
            return f"Found {len(results)} asset(s) (total {payload.get('total', len(results))})"
    if name == "get_asset_details":
        asset = payload.get("asset") or payload
        if isinstance(asset, dict):
            disp = asset.get("displayName") or asset.get("name") or "asset"
            return f"Details for {disp}"
    if name in {"get_table_semantics", "get_column_semantics", "get_business_term_data", "get_measure_data"}:
        return f"{status}: Graph semantics resolved"
    if name in {"discover_business_glossary", "discover_data_assets"}:
        results = payload.get("results")
        if isinstance(results, list):
            return f"Found {len(results)} item(s)"
    if name == "prepare_create_asset":
        domains = payload.get("domainOptions")
        if isinstance(domains, list):
            return f"Found {len(domains)} catalog domain(s)"
        types = payload.get("assetTypeOptions")
        if isinstance(types, list):
            return f"Found {len(types)} asset type(s)"
        return str(status)
    if name == "list_asset_types":
        types = payload.get("assetTypes")
        if isinstance(types, list):
            return f"Found {len(types)} asset type(s)"
        return str(status)
    return str(status)


class LlmError(RuntimeError):
    """The model endpoint refused or could not be reached."""


class ChatLlm:
    """OpenAI-compatible chat completions, including Azure OpenAI."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        kind: str = "openai",
        azure_api_version: str = "2024-10-21",
        timeout_seconds: float = 90.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.kind = kind.lower()
        self.azure_api_version = azure_api_version
        self.timeout_seconds = timeout_seconds

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        if self.kind == "azure":
            url = (
                f"{self.base_url}/openai/deployments/{self.model}/chat/completions"
                f"?api-version={self.azure_api_version}"
            )
            headers = {"api-key": self.api_key, "Content-Type": "application/json"}
            body: dict[str, Any] = {"messages": messages, "tools": tools, "tool_choice": "auto"}
        else:
            url = f"{self.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            body = {
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
            }
        try:
            response = httpx.post(url, headers=headers, json=body, timeout=self.timeout_seconds)
        except httpx.HTTPError as exc:
            raise LlmError(f"Could not reach the language-model endpoint: {exc}") from exc
        if response.status_code >= 400:
            raise LlmError(
                f"Language-model endpoint returned HTTP {response.status_code}: "
                f"{response.text[:400]}"
            )
        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise LlmError("Language-model endpoint returned no choices.")
        return choices[0]["message"]


class ChatAgent:
    """Runs one user question through the tool loop and returns a final answer."""

    def __init__(
        self,
        service: ToolService,
        llm: ChatLlm | None,
        collibra: CollibraClient | None = None,
    ) -> None:
        self.service = service
        self.llm = llm
        self.collibra = collibra
        self._dispatch: dict[str, Callable[..., dict[str, Any]]] = {
            "list_databases": lambda **_: service.list_databases(),
            "list_allowed_schemas": service.list_allowed_schemas,
            "list_allowed_tables": service.list_allowed_tables,
            "get_table_metadata": service.get_table_metadata,
            "search_data_dictionary": service.search_data_dictionary,
            "validate_sql": service.validate_sql,
            "execute_readonly_sql": self._execute,
            "explain_query_result": service.explain_query_result,
            "compare_onprem_and_atp_data": service.compare_onprem_and_atp_data,
        }

    def _execute(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.pop("user_role", None)
        kwargs.setdefault("user_id", self.service.settings.pinned_user_id)
        return self.service.execute_readonly_sql(**kwargs)

    def invoke_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name in COLLIBRA_TOOL_NAMES or (self.collibra and name in {t["function"]["name"] for t in self.collibra.list_tools()}):
            if self.collibra is None:
                return {
                    "status": "ERROR",
                    "error_code": "COLLIBRA_NOT_CONFIGURED",
                    "message": "Collibra MCP client is not configured. Enable COLLIBRA_MCP_ENABLED in .env.",
                }
            return self.collibra.invoke_tool(name, arguments)

        fn = self._dispatch.get(name)
        if fn is None:
            return {
                "status": "ERROR",
                "error_code": "UNKNOWN_TOOL",
                "message": f"{name} is not an available tool on this server.",
            }
        if name == "compare_onprem_and_atp_data" and not self.service.settings.reconciliation_enabled:
            return {
                "status": "ERROR",
                "error_code": "TOOL_UNAVAILABLE",
                "message": "Reconciliation requires this process to serve both ONPREM and ATP (ORACLE_MCP_PROFILE=both).",
            }
        cleaned = {k: v for k, v in arguments.items() if k != "user_role"}
        try:
            return fn(**cleaned)
        except TypeError as exc:
            return {
                "status": "ERROR",
                "error_code": "BAD_TOOL_ARGS",
                "message": str(exc),
            }

    def run(
        self,
        question: str,
        history: list[dict[str, str]] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if self.llm is None:
            raise LlmError(
                "No language model is configured. Set CHAT_LLM_API_KEY and "
                "CHAT_LLM_MODEL (and CHAT_LLM_BASE_URL) in .env."
            )

        def emit(event: dict[str, Any]) -> None:
            if on_event is not None:
                on_event(event)

        tools = tools_for(self.service, self.collibra)
        messages: list[dict[str, Any]] = [{"role": "system", "content": load_system_prompt()}]
        for turn in history or []:
            role = turn.get("role")
            content = turn.get("content")
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": question})

        trace: list[dict[str, Any]] = []
        answer = ""
        nudged = False
        for _ in range(_MAX_TOOL_ROUNDS):
            message = self.llm.complete(messages, tools)
            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                answer = (message.get("content") or "").strip()
                # Sent back once, and only when nothing was discovered at all.
                # A model that has read the metadata and still needs a decision
                # is asking legitimately; one that asks before touching a tool
                # is guessing, and its attribute lists come from memory.
                if not trace and not nudged and asks_instead_of_discovering(answer):
                    nudged = True
                    emit({"type": "tool", "name": "discovery_required", "status": "start", "arguments": {}})
                    messages.append(message)
                    messages.append({"role": "user", "content": _DISCOVERY_NUDGE})
                    emit(
                        {
                            "type": "tool",
                            "name": "discovery_required",
                            "status": "done",
                            "summary": "Answered with no tool call; required metadata discovery before answering.",
                        }
                    )
                    continue
                break
            messages.append(message)
            for call in tool_calls:
                fn = call.get("function") or {}
                name = fn.get("name") or ""
                raw_args = fn.get("arguments") or "{}"
                try:
                    arguments = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except json.JSONDecodeError:
                    arguments = {}
                emit({"type": "tool", "name": name, "status": "start", "arguments": arguments})
                result = self.invoke_tool(name, arguments)
                summary = summarise_tool_result(name, result if isinstance(result, dict) else {})
                trace.append({"name": name, "arguments": arguments, "summary": summary})
                emit({"type": "tool", "name": name, "status": "done", "summary": summary})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id") or name,
                        "content": compact_tool_result(result),
                    }
                )
        else:
            answer = (
                "I reached the tool-call limit before finishing. Ask a narrower "
                "question, or name the schema and table if you know them."
            )

        emit({"type": "message", "text": answer})
        return {"answer": answer, "tools": trace}


def iter_sse(payloads: Iterator[dict[str, Any]]) -> Iterator[str]:
    for event in payloads:
        name = event.get("type", "message")
        data = json.dumps(event, default=str, ensure_ascii=False)
        yield f"event: {name}\ndata: {data}\n\n"
    yield "event: done\ndata: {}\n\n"
