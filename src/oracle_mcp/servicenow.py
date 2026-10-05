"""ServiceNow MCP client for the standalone chat agent.

Read-only. MDM incident details and analysis cover CDM and EIM and come from
ServiceNow, not from Oracle. The gateway is the same NetApp AI Gateway used
for Collibra.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .collibra import _parse_json_or_sse

logger = logging.getLogger(__name__)

DEFAULT_SERVICENOW_URL = (
    "https://netaigateway.netapp.com/api/llm/netaiconnect/mcp/servicenow/server"
)
_MAX_ROWS = 100

# MDM support queues. Names contain ">", so filters use the group sys_id.
MDM_INCIDENT_GROUPS: dict[str, dict[str, str]] = {
    "CDM": {
        "name": "IT > MDM > CDM",
        "sys_id": "54ee35bb1b9db6dc358e0d03604bcb63",
    },
    "EIM": {
        "name": "IT > MDM > EIM",
        "sys_id": "3015d29b789302402bb290716e4bea0c",
    },
}
_STATE_LABELS = {
    "1": "New",
    "2": "In Progress",
    "3": "On Hold",
    "6": "Resolved",
    "7": "Closed",
    "8": "Canceled",
}
_PRIORITY_LABELS = {
    "1": "Critical",
    "2": "High",
    "3": "Moderate",
    "4": "Low",
    "5": "Planning",
}
_INCIDENT_FIELDS = [
    "number",
    "short_description",
    "state",
    "priority",
    "assignment_group",
    "assigned_to",
    "opened_at",
    "sys_updated_on",
    "sys_id",
]

SERVICENOW_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "servicenow_get_authenticated_user",
            "description": (
                "Return the ServiceNow user for this session. The client calls "
                "this before the first data query. Use the sys_id only when the "
                "question is about the signed-in person's own tickets."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_mdm_incidents",
            "description": (
                "Incident details and analysis for MDM. MDM means both CDM "
                "(IT > MDM > CDM) and EIM (IT > MDM > EIM). Use this for open "
                "tickets, incident counts, assignee load, state mix, priority "
                "mix, or an analysis of CDM, EIM, or both. Do not use Oracle. "
                "Quote active_incidents, working_incidents, "
                "resolved_still_active, by_group, by_state, by_priority, "
                "by_assignee, and the incident list. scope mdm is both groups; "
                "use cdm or eim only when the question names one."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["mdm", "cdm", "eim"],
                        "description": "mdm covers CDM and EIM. Default mdm.",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_query_table",
            "description": (
                "Query one ServiceNow table. For an MDM, CDM, or EIM incident "
                "overview or analysis, call summarize_mdm_incidents instead. "
                "Use this query only for a follow-up on one record or a table "
                "other than the MDM incident queues. Do not create, update, "
                "or delete records."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {"type": "string", "description": "ServiceNow table name, such as incident."},
                    "query": {"type": "string", "description": "Encoded query. ^ is AND."},
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Columns to return.",
                    },
                    "limit": {"type": "integer", "description": "Maximum rows, 1 to 100."},
                    "offset": {"type": "integer", "description": "Rows to skip."},
                },
                "required": ["table"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_get_record",
            "description": "Get one ServiceNow record by table and sys_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {"type": "string"},
                    "sysId": {"type": "string", "description": "32-character sys_id, not the INC number."},
                    "fields": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["table", "sysId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_aggregate_table",
            "description": (
                "Count or group ServiceNow records. Use this for how many open "
                "MDM or EIM tickets, grouped by state or priority."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {"type": "string"},
                    "query": {"type": "string"},
                    "count": {"type": "boolean"},
                    "groupBy": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["table"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_list_tables",
            "description": "Find a ServiceNow table by name or label.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_describe_table",
            "description": "List columns for a ServiceNow table before querying an unfamiliar field.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["table"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "servicenow_search_knowledge",
            "description": "Search ServiceNow knowledge articles the signed-in user can read.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
        },
    },
]

SERVICENOW_TOOL_NAMES = {spec["function"]["name"] for spec in SERVICENOW_TOOL_SPECS}


def mdm_incident_scope(scope: str) -> list[str]:
    """Return CDM, EIM, or both. MDM means both queues."""
    key = (scope or "mdm").strip().lower()
    if key == "cdm":
        return ["CDM"]
    if key == "eim":
        return ["EIM"]
    return ["CDM", "EIM"]


def _label(code: Any, labels: dict[str, str]) -> str:
    text = "" if code is None else str(code)
    if text in labels:
        return f"{text} {labels[text]}"
    return f"State {text}" if text else "Unknown"


def _result_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    response = payload.get("response")
    if isinstance(response, dict) and isinstance(response.get("result"), list):
        return [row for row in response["result"] if isinstance(row, dict)]
    result = payload.get("result")
    if isinstance(result, list):
        return [row for row in result if isinstance(row, dict)]
    return []


def analyze_mdm_incidents(
    rows: list[dict[str, Any]],
    users: list[dict[str, Any]],
    *,
    scope: str,
) -> dict[str, Any]:
    """Turn CDM and EIM incident rows into counts and a detail list."""
    group_by_id = {
        info["sys_id"]: label for label, info in MDM_INCIDENT_GROUPS.items()
    }
    names = {
        str(user.get("sys_id")): user.get("name") or user.get("user_name")
        for user in users
        if user.get("sys_id")
    }
    incidents: list[dict[str, Any]] = []
    for row in rows:
        assignee_id = str(row.get("assigned_to") or "")
        state_code = str(row.get("state") or "")
        priority_code = str(row.get("priority") or "")
        incidents.append(
            {
                "number": row.get("number"),
                "group": group_by_id.get(str(row.get("assignment_group") or ""), "Unknown"),
                "state": _label(state_code, _STATE_LABELS),
                "state_code": state_code,
                "priority": _label(priority_code, _PRIORITY_LABELS).replace("State ", "Priority "),
                "assigned_to": names.get(assignee_id) or ("Unassigned" if not assignee_id else assignee_id),
                "opened_at": row.get("opened_at"),
                "updated_at": row.get("sys_updated_on"),
                "short_description": row.get("short_description"),
                "sys_id": row.get("sys_id"),
            }
        )

    def tally(key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in incidents:
            label = str(item.get(key) or "Unknown")
            counts[label] = counts.get(label, 0) + 1
        return dict(sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])))

    working = [item for item in incidents if item["state_code"] not in {"6", "7", "8"}]
    resolved = [item for item in incidents if item["state_code"] == "6"]
    canceled = [item for item in incidents if item["state_code"] == "8"]
    selected = mdm_incident_scope(scope)
    return {
        "scope": "mdm" if selected == ["CDM", "EIM"] else selected[0].lower(),
        "groups": [MDM_INCIDENT_GROUPS[label]["name"] for label in selected],
        "active_incidents": len(incidents),
        "working_incidents": len(working),
        "resolved_still_active": len(resolved),
        "canceled_still_active": len(canceled),
        "unassigned": sum(1 for item in incidents if item["assigned_to"] == "Unassigned"),
        "by_group": tally("group"),
        "by_state": tally("state"),
        "by_priority": tally("priority"),
        "by_assignee": tally("assigned_to"),
        "incidents": working + resolved + canceled,
    }


class ServiceNowClient:
    """HTTP client for the ServiceNow MCP server on the NetApp AI Gateway."""

    def __init__(
        self,
        url: str = DEFAULT_SERVICENOW_URL,
        api_key: str = "",
        timeout_seconds: float = 60.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._session_id = ""
        self._initialized = False
        self._identity_ready = False

    def list_tools(self) -> list[dict[str, Any]]:
        return SERVICENOW_TOOL_SPECS

    def invoke_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if name not in SERVICENOW_TOOL_NAMES:
            return {
                "status": "ERROR",
                "error_code": "READONLY",
                "message": (
                    "This chatbot's ServiceNow connection is read-only. "
                    f"{name} is not available."
                ),
            }
        if name != "servicenow_get_authenticated_user" and not self._identity_ready:
            identity = self._call("servicenow_get_authenticated_user", {})
            if identity.get("status") == "ERROR":
                return identity
            self._identity_ready = True
        args = dict(arguments or {})
        if name == "summarize_mdm_incidents":
            return self._summarize_mdm_incidents(str(args.get("scope") or "mdm"))
        return self._call(name, args)

    def _summarize_mdm_incidents(self, scope: str) -> dict[str, Any]:
        selected = mdm_incident_scope(scope)
        group_ids = ",".join(MDM_INCIDENT_GROUPS[label]["sys_id"] for label in selected)
        incidents = self._call(
            "servicenow_query_table",
            {
                "table": "incident",
                "query": (
                    "active=true^assignment_groupIN"
                    f"{group_ids}^ORDERBYDESCsys_updated_on"
                ),
                "fields": _INCIDENT_FIELDS,
                "limit": _MAX_ROWS,
            },
        )
        if incidents.get("status") == "ERROR":
            return incidents
        rows = _result_rows(incidents)
        assignee_ids = sorted({str(row.get("assigned_to")) for row in rows if row.get("assigned_to")})
        users: list[dict[str, Any]] = []
        if assignee_ids:
            people = self._call(
                "servicenow_query_table",
                {
                    "table": "sys_user",
                    "query": "sys_idIN" + ",".join(assignee_ids),
                    "fields": ["sys_id", "name", "user_name"],
                    "limit": _MAX_ROWS,
                },
            )
            if people.get("status") != "ERROR":
                users = _result_rows(people)
        summary = analyze_mdm_incidents(rows, users, scope=scope)
        summary["truncated"] = bool(incidents.get("truncated")) or len(rows) >= _MAX_ROWS
        group_names = " and ".join(MDM_INCIDENT_GROUPS[label]["name"] for label in selected)
        summary["definition"] = (
            f"Active ServiceNow incidents assigned to {group_names}. "
            "Working excludes Resolved (6), Closed (7), and Canceled (8). "
            "Resolved incidents can still be active."
        )
        return summary

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream, */*",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _ensure_initialized(self) -> dict[str, Any] | None:
        """Open an MCP session before the first tool call.

        ServiceNow rejects tools/call with "Server not initialized" until the
        client sends initialize and notifications/initialized on that session.
        """
        if self._initialized:
            return None
        started = self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mdm-data-assistant", "version": "1.0.0"},
                },
            }
        )
        if started.get("status") == "ERROR":
            return started
        confirmed = self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        if confirmed.get("status") == "ERROR":
            return confirmed
        self._initialized = True
        return None

    def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        pending = self._ensure_initialized()
        if pending is not None:
            return pending
        if name == "servicenow_query_table":
            limit = arguments.get("limit")
            try:
                arguments["limit"] = min(int(limit), _MAX_ROWS) if limit else 50
            except (TypeError, ValueError):
                arguments["limit"] = 50
        return self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(
                self.url,
                headers=self._headers(),
                json=payload,
                timeout=self.timeout_seconds,
            )
        except httpx.HTTPError as exc:
            return {
                "status": "ERROR",
                "error_code": "NETWORK_ERROR",
                "message": f"Could not reach ServiceNow MCP server: {exc}",
            }
        session_id = response.headers.get("mcp-session-id") or response.headers.get("Mcp-Session-Id")
        if session_id:
            self._session_id = session_id
        if payload.get("method") == "notifications/initialized" and response.status_code < 400:
            return {"status": "OK"}
        if response.status_code == 401:
            return {
                "status": "ERROR",
                "error_code": "UNAUTHORIZED",
                "message": (
                    "ServiceNow MCP server returned 401 Unauthorized. Verify "
                    "CHAT_LLM_API_KEY / SERVICENOW_MCP_API_KEY contains a valid gateway token."
                ),
            }
        if response.status_code >= 400:
            return {
                "status": "ERROR",
                "error_code": f"HTTP_{response.status_code}",
                "message": (
                    f"ServiceNow MCP server returned HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                ),
            }
        data = _parse_json_or_sse(response.text)
        if data is None:
            return {
                "status": "ERROR",
                "error_code": "INVALID_JSON",
                "message": f"ServiceNow MCP server returned non-JSON response: {response.text[:200]}",
            }
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            return {
                "status": "ERROR",
                "error_code": str(err.get("code", "MCP_ERROR")),
                "message": str(err.get("message", "Error from ServiceNow MCP server")),
            }
        result = data.get("result", data) if isinstance(data, dict) else data
        if isinstance(result, dict) and "content" in result:
            if result.get("isError"):
                return {
                    "status": "ERROR",
                    "error_code": "SERVICENOW_TOOL_ERROR",
                    "message": _content_text(result) or "ServiceNow tool call failed.",
                }
            text = _content_text(result)
            parsed = _parse_json_or_sse(text) if text else None
            if isinstance(parsed, dict):
                return parsed
            if text:
                return {"status": "OK", "result": text}
        return result if isinstance(result, dict) else {"status": "OK", "result": result}


def _content_text(result: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
            parts.append(str(item["text"]))
    return "\n".join(parts)
