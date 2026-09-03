"""Collibra Data Governance Cloud MCP Client.

Connects to the Collibra MCP server over HTTP (e.g. via NetApp AI Gateway)
to provide data governance, catalog metadata, business terms, lineage, and
classifications to the standalone chat agent.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_COLLIBRA_URL = (
    "https://netaigateway.netapp.com/api/llm/netaiconnect/mcp/collibramcp/server"
)

# Curated standard Collibra tool specifications
COLLIBRA_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_asset_keyword",
            "description": (
                "Perform a wildcard keyword search for assets, communities, or domains "
                "in the Collibra knowledge graph. Supports filtering by resource type, "
                "community, domain, asset type, status, and creator."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Required. The keyword query to search for.",
                    },
                    "resourceTypeFilters": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Supported values: Asset, Domain, Community, User, UserGroup.",
                    },
                    "communityFilter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Filter by community names or UUIDs.",
                    },
                    "domainFilter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Filter by domain names or UUIDs.",
                    },
                    "assetTypeFilter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Filter by asset type names (e.g. Table, Column, Business Term, Data Attribute) or UUIDs.",
                    },
                    "statusFilter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Filter by status names (e.g. Approved, Under Review, Draft).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Optional. Maximum number of results to return (default 50, max 1000).",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Optional. Index of first result for pagination.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_asset_details",
            "description": (
                "Get detailed information about a specific Collibra asset by its UUID, "
                "including attributes, relations, responsibilities (stewards, owners), "
                "and status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Required. The UUID of the asset to retrieve details for.",
                    },
                    "incomingRelationsCursor": {
                        "type": "string",
                        "description": "Optional. Cursor to fetch next page of incoming relations.",
                    },
                    "outgoingRelationsCursor": {
                        "type": "string",
                        "description": "Optional. Cursor to fetch next page of outgoing relations.",
                    },
                },
                "required": ["assetId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_table_semantics",
            "description": (
                "Walk the semantic graph from a Table asset UUID to its Columns, Data "
                "Attributes, and Business Terms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Required. Table asset UUID.",
                    },
                },
                "required": ["assetId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_column_semantics",
            "description": (
                "Walk the semantic graph from a Column asset UUID to its Data Attribute "
                "and Business Term."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Required. Column asset UUID.",
                    },
                },
                "required": ["assetId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_business_term_data",
            "description": (
                "Walk the semantic graph from a Business Term UUID to connected physical "
                "columns and tables."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Required. Business Term asset UUID.",
                    },
                },
                "required": ["assetId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_measure_data",
            "description": (
                "Trace a KPI or Measure asset UUID to its data attributes, columns, and "
                "source tables."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Required. Measure/KPI asset UUID.",
                    },
                },
                "required": ["assetId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_lineage_entities",
            "description": (
                "Find technical lineage entity IDs by name or type to use as entry points "
                "for upstream/downstream lineage impact analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Required. Name of the entity to find in lineage.",
                    },
                    "type": {
                        "type": "string",
                        "description": "Optional entity type filter.",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_lineage_upstream",
            "description": (
                "Get upstream technical lineage for an entity ID to trace source systems "
                "and data transformations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "entityId": {
                        "type": "string",
                        "description": "Required. Lineage entity ID from search_lineage_entities.",
                    },
                },
                "required": ["entityId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_lineage_downstream",
            "description": (
                "Get downstream technical lineage for an entity ID to trace downstream "
                "impact, reports, and destinations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "entityId": {
                        "type": "string",
                        "description": "Required. Lineage entity ID from search_lineage_entities.",
                    },
                },
                "required": ["entityId"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_data_class",
            "description": (
                "Search data classifications (e.g. PII, PHI, Confidentiality taxonomies) "
                "in Collibra."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Required. Classification name or keyword.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_data_classification_match",
            "description": (
                "Find data classification matches on assets (which columns/assets match a "
                "data class)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetId": {
                        "type": "string",
                        "description": "Optional. Asset UUID to inspect classifications for.",
                    },
                    "classificationId": {
                        "type": "string",
                        "description": "Optional. Data classification UUID.",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "discover_business_glossary",
            "description": (
                "Semantic natural-language search across Collibra business glossary terms. "
                "Requires dgc.ai-copilot scope. If forbidden, use search_asset_keyword instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Required. Natural language query.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "discover_data_assets",
            "description": (
                "Semantic natural-language search across Collibra data assets (tables, columns). "
                "Requires dgc.ai-copilot scope. If forbidden, use search_asset_keyword instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Required. Natural language query.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_asset_types",
            "description": "List available asset types defined in Collibra.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
]

COLLIBRA_TOOL_NAMES = {spec["function"]["name"] for spec in COLLIBRA_TOOL_SPECS}


def _parse_json_or_sse(raw: str) -> dict[str, Any] | list[Any] | None:
    """Parse a payload that may be direct JSON or an SSE (Server-Sent Events) stream.

    Many HTTP MCP servers (including NetApp AI Gateway) stream responses as:
        event: message
        data: {"jsonrpc": "2.0", "id": 1, "result": {...}}
    """
    if not raw or not isinstance(raw, str):
        return None

    stripped = raw.strip()

    # 1. Direct JSON parse
    try:
        obj = json.loads(stripped)
        if isinstance(obj, (dict, list)):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass

    # 2. SSE line-by-line parsing
    events: list[dict[str, Any]] = []
    current_data_lines: list[str] = []

    def flush_chunk() -> None:
        if not current_data_lines:
            return
        chunk = "\n".join(current_data_lines).strip()
        current_data_lines.clear()
        if not chunk or chunk == "[DONE]":
            return
        try:
            parsed = json.loads(chunk)
            if isinstance(parsed, (dict, list)):
                events.append(parsed)  # type: ignore[arg-type]
                return
        except (json.JSONDecodeError, ValueError):
            pass

        # Try to find embedded JSON substring inside the chunk
        start = chunk.find("{")
        end = chunk.rfind("}")
        if start != -1 and end > start:
            try:
                sub = json.loads(chunk[start : end + 1])
                if isinstance(sub, (dict, list)):
                    events.append(sub)  # type: ignore[arg-type]
            except (json.JSONDecodeError, ValueError):
                pass

    for line in raw.splitlines():
        line_str = line.strip()
        if not line_str:
            flush_chunk()
            continue
        if line_str.startswith("data:"):
            current_data_lines.append(line_str[5:].strip())
        elif line_str.startswith(("event:", "id:", "retry:")):
            continue
        else:
            if current_data_lines:
                current_data_lines.append(line_str)

    flush_chunk()

    # Look for JSON-RPC standard response containing result or error
    for ev in reversed(events):
        if isinstance(ev, dict) and ("result" in ev or "error" in ev):
            return ev

    if events:
        return events[-1]

    # 3. Last fallback: search for outermost JSON object/array in entire raw text
    for open_ch, close_ch in [("{", "}"), ("[", "]")]:
        start = raw.find(open_ch)
        end = raw.rfind(close_ch)
        if start != -1 and end > start:
            try:
                candidate = json.loads(raw[start : end + 1])
                if isinstance(candidate, (dict, list)):
                    return candidate
            except (json.JSONDecodeError, ValueError):
                pass

    return None


class CollibraClient:
    """HTTP Client for Collibra MCP server (NetApp AI Gateway or direct MCP)."""

    def __init__(
        self,
        url: str = DEFAULT_COLLIBRA_URL,
        api_key: str = "",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._cached_tools: list[dict[str, Any]] | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream, */*",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def list_tools(self) -> list[dict[str, Any]]:
        """Return available Collibra tool specifications."""
        if self._cached_tools is not None:
            return self._cached_tools
        return COLLIBRA_TOOL_SPECS

    def invoke_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call to the Collibra MCP endpoint via JSON-RPC 2.0."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        }
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
                "message": f"Could not reach Collibra MCP server: {exc}",
            }

        if response.status_code == 401:
            return {
                "status": "ERROR",
                "error_code": "UNAUTHORIZED",
                "message": (
                    "Collibra MCP server returned 401 Unauthorized. Verify "
                    "CHAT_LLM_API_KEY / COLLIBRA_MCP_API_KEY contains a valid gateway token."
                ),
            }
        if response.status_code == 403:
            return {
                "status": "ERROR",
                "error_code": "FORBIDDEN",
                "message": (
                    f"Collibra MCP server returned 403 Forbidden: {response.text[:300]}. "
                    "Ensure your user has the required Collibra scopes (e.g. dgc.ai-copilot, dgc.catalog)."
                ),
            }
        if response.status_code >= 400:
            return {
                "status": "ERROR",
                "error_code": f"HTTP_{response.status_code}",
                "message": f"Collibra MCP server returned HTTP {response.status_code}: {response.text[:300]}",
            }

        raw_text = response.text
        data = _parse_json_or_sse(raw_text)

        if data is None:
            if response.status_code == 200 and raw_text.strip():
                return {
                    "status": "OK",
                    "result": raw_text.strip(),
                }
            return {
                "status": "ERROR",
                "error_code": "INVALID_JSON",
                "message": f"Collibra MCP server returned non-JSON response: {raw_text[:200]}",
            }

        if isinstance(data, dict) and "error" in data and data["error"]:
            err = data["error"]
            return {
                "status": "ERROR",
                "error_code": str(err.get("code", "MCP_ERROR")),
                "message": str(err.get("message", "Error from Collibra MCP server")),
                "data": err.get("data"),
            }

        result = data.get("result", {}) if isinstance(data, dict) else data
        # MCP tools/call standard returns {"content": [{"type": "text", "text": "..."}]}
        if isinstance(result, dict) and "content" in result:
            content = result["content"]
            if isinstance(content, list) and len(content) > 0:
                text_parts: list[str] = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        t = item.get("text", "")
                        if t:
                            text_parts.append(t)
                if text_parts:
                    combined = "\n".join(text_parts)
                    inner = _parse_json_or_sse(combined)
                    if inner is not None and isinstance(inner, (dict, list)):
                        return inner  # type: ignore[return-value]
                    return {"result": combined}
            return result
        return result
