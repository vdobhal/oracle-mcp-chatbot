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
                "Perform a wildcard keyword search in the Collibra knowledge graph for "
                "Assets, Domains, or Communities. When searching for a domain, community, "
                "or catalog location (e.g. 'IB Attributes', 'Install Base Master', 'Master Data Management'), "
                "use resourceTypeFilters=['Community', 'Domain']. Once a Community/Domain UUID is found, "
                "use communityFilter or domainFilter to inspect the domains and assets inside it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Required. The keyword query to search for (or '*' when filtering by community/domain).",
                    },
                    "resourceTypeFilters": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional. Supported values: Asset, Domain, Community, User, UserGroup. Use ['Community', 'Domain'] when locating domains or catalog hierarchy.",
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
                    "tableId": {
                        "type": "string",
                        "description": "Required. Table asset UUID.",
                    },
                },
                "required": ["tableId"],
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
                    "columnId": {
                        "type": "string",
                        "description": "Required. Column asset UUID.",
                    },
                },
                "required": ["columnId"],
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
                    "businessTermId": {
                        "type": "string",
                        "description": "Required. Business Term asset UUID.",
                    },
                },
                "required": ["businessTermId"],
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
                    "measureId": {
                        "type": "string",
                        "description": "Required. Measure/KPI asset UUID.",
                    },
                },
                "required": ["measureId"],
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
            "name": "prepare_create_asset",
            "description": (
                "Enumerate available asset types and all 196 catalog domains defined in Collibra, "
                "or inspect the schema and attributes of a domain or asset type. "
                "Use this tool to discover domains, domain UUIDs, and domain types."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assetType": {
                        "type": "string",
                        "description": "Optional. Asset type name or UUID (e.g. 'Data Attribute', 'Business Term').",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Optional. Domain name or UUID.",
                    },
                },
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


GOVERNED_IB_CATALOG = [
    {
        "id": "81e4cbc9-b20c-446c-8672-2617c153e327",
        "name": "IB Mastering (EIM) and Management (IBDP)",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("8d4330f7-3d32-4106-aaca-28111ad71d1d", "Serial Number", "Data Attribute", "Under Review"),
            ("8fbc711e-0b69-473a-8da4-6e89d28ac899", "Partner Serial Number", "Data Attribute", "Under Review"),
            ("50887cf8-a140-46ec-847a-bdac22918e9b", "Product Series", "Data Attribute", "Approved"),
            ("bd03e774-bc99-4fd2-a3de-7565e7f76c01", "Product Series Category", "Data Attribute", "Approved"),
            ("746b90af-345c-4273-9bb7-7c60e86bd0c9", "Product Series Sub Category", "Data Attribute", "Approved"),
            ("4f655c85-526e-4290-ab5a-774470d1ff5d", "Platform", "Data Attribute", "Approved"),
            ("de84a3ef-1984-40ce-a93e-525015022148", "OS Version Number", "Data Attribute", "Under Review"),
            ("88475b9b-bf6b-4cab-a5e5-a8d8f71e86a1", "Simplified OS Version", "Data Attribute", "Under Review"),
            ("4713ce7f-8562-4c7f-b09a-962f8e0615b3", "Original Ship Date", "Data Attribute", "Under Review"),
            ("fa92ce89-9703-44af-b560-2b1a563e8bba", "EOS Date", "Data Attribute", "Approved"),
            ("f02eac94-92bb-4409-b961-e3473d69fc7b", "System Age", "Data Attribute", "Under Review"),
            ("f813b638-97ee-48c3-9d52-ee8382d3c944", "IB Group ID", "Data Attribute", "Under Review"),
            ("e754586d-dff3-4ac4-814b-537e69dd666e", "IB Marketing Part Number", "Data Attribute", "Under Review"),
            ("11cff8c0-1f7c-4a7d-9c89-db4c4d0917a2", "MetroCluster Flag", "Data Attribute", "Under Review"),
        ],
    },
    {
        "id": "972d327f-c854-4233-9c99-98aca34d897a",
        "name": "Best Known Configuration Mastering (EIM) and Management (IBDP)",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("33f8c3e0-4eff-49bd-9e0c-96ea9f64355c", "AS Renewed Hardware Pricing Part Number", "Data Attribute", "Approved"),
            ("bf920f2d-3120-49e7-aa0b-5f4981c1e0c9", "As Renewed OS Pricing Part Number", "Data Attribute", "Approved"),
            ("0699b667-16c2-4580-8042-f85f240b52c0", "As Renewed Software Pricing Part Number", "Data Attribute", "Approved"),
            ("36df1f94-5503-470f-8584-51878bedeca9", "As Renewed Storage Pricing Part Number", "Data Attribute", "Approved"),
            ("2d4f9347-9c4e-41bc-b649-cc5baeb62336", "Best Known Configuration (BKC)", "Data Attribute", "Approved"),
            ("2a3fdfc5-6d1a-49e0-b95e-1fc4566e43a3", "Booked Date", "Data Attribute", "Approved"),
            ("15a75b15-f74b-4038-9529-68af4391ee27", "Config Level - Component and below", "Data Attribute", "Approved"),
            ("6f53a5a9-ef65-4e27-8586-f2c22a57a2f0", "Config Level - Component only", "Data Attribute", "Approved"),
            ("6aea5694-8922-4b7e-981d-f1d3fedbaccf", "Config Level - Parent", "Data Attribute", "Approved"),
            ("df175cfd-839a-496e-9820-2596b34e2573", "Config Level - Root", "Data Attribute", "Approved"),
            ("7c130a05-c43a-4741-bdcd-526b023d5b04", "Config Version - As Maintained", "Data Attribute", "Approved"),
            ("c088b189-0a33-4182-989e-b0a52a527324", "Config Version - As of Date", "Data Attribute", "Approved"),
            ("036df8a3-90cd-4d16-8a5c-b647e2b3da5a", "Config Version - As Shipped", "Data Attribute", "Approved"),
            ("cb116ad2-6eb9-486d-b53d-2fa36a840f46", "Config version - as sold", "Data Attribute", "Approved"),
            ("d591f2c1-af6d-4282-97d8-3e5bd0ea8fc2", "Config View - V1", "Data Attribute", "Approved"),
            ("65976158-dd07-418e-93c2-60262d140664", "Config View - V2", "Data Attribute", "Approved"),
            ("f1fa443b-8fa9-4f71-91a4-86494f3d5831", "Disk Count for Controller", "Data Attribute", "Approved"),
            ("d7ca724e-ecd5-4d4c-8a1d-68e9b2029d30", "Eligibility Flag", "Data Attribute", "Approved"),
            ("5a5c3dc3-09ed-46d0-9986-5fff3508d633", "Eligible Discount", "Data Attribute", "Approved"),
            ("ba6a68d8-30dc-4bb8-bfe9-8e0b696c9a01", "Flash Cache Category", "Data Attribute", "Approved"),
            ("084652cc-356c-467f-b76b-f21913d29a2b", "Flash Cache Marketing Part Number", "Data Attribute", "Approved"),
            ("e957b7d9-d33a-4417-90f4-23fb8c6a010e", "Flash Cache Part Number", "Data Attribute", "Approved"),
            ("7cd4f7c6-8c92-496a-9294-920c047f558f", "Flash Cache Serial Number", "Data Attribute", "Approved"),
            ("2007d4d6-6e39-4f29-94f0-2bf4570b02e9", "Install Base(SN) Node Pair", "Data Attribute", "Approved"),
            ("0a40a507-c001-4949-b438-a8c161578d36", "LATEST CONFIG FLAG", "Data Attribute", "Approved"),
            ("53619fac-2065-4372-9a2d-1959080c3288", "Part Number", "Data Attribute", "Approved"),
            ("42661953-83bc-4a63-ab41-0b1e22aeeb1d", "Part Type", "Data Attribute", "Approved"),
            ("d9e67bb7-2eed-40cd-a22e-e4aebe36fa79", "PARTNER SERIAL NUMBER", "Data Attribute", "Approved"),
            ("4a64078e-e426-446f-be36-9986669d0496", "QUANTITY", "Data Attribute", "Approved"),
            ("98207b20-baf2-45d3-b2ca-e40fef68df24", "Quote Line ID", "Data Attribute", "Approved"),
            ("60ece8c8-796d-4507-85e8-8e5f7fc341da", "Quote Number", "Data Attribute", "Approved"),
            ("5cb9cbd2-0163-4872-8bb7-c64917cafcc0", "QUOTE UPDATE DATE", "Data Attribute", "Approved"),
            ("b3445778-54a9-4cf8-a97d-e52ed2578893", "Renewal Order Number", "Data Attribute", "Approved"),
            ("69725f29-2225-4516-b8c1-71f4d4a7d734", "Shelf Count for Controller", "Data Attribute", "Approved"),
            ("21f6021c-8062-40c9-91b0-b449b77e66f4", "System - BKC", "Data Attribute", "Approved"),
            ("16f70dd1-7e3e-461c-910e-e42880b7d6bc", "System Level Eligible Discount", "Data Attribute", "Approved"),
            ("43044933-c978-41d7-be36-cef4eda3b8f1", "System Level Eligibility Flag", "Data Attribute", "Approved"),
            ("fdde3e18-320c-4aa4-9187-64cb012b0b47", "SYSTEM SERIAL NUMBER", "Data Attribute", "Approved"),
            ("826398cc-dbbc-4981-ac2e-6468e0b24849", "Total MKTG Disk Capacity for Controller", "Data Attribute", "Approved"),
            ("780a9fc4-1e26-4944-aa12-b386b544af45", "Total MKTG SSD Disk Capacity for Controller", "Data Attribute", "Approved"),
            ("742da891-3004-41d6-9e19-766145b1a40b", "Transaction Level Eligible Discount", "Data Attribute", "Approved"),
            ("546eb74f-0bcd-48c3-9b16-3110aa954840", "Transaction Level Eligibility Flag", "Data Attribute", "Approved"),
            ("2bee4a6f-4bfc-48a0-98c2-227712f3a40b", "Virtual Config ID", "Data Attribute", "Approved"),
            ("c24f63f8-a501-4a2d-94d9-35d8a693e3e0", "VIRTUAL CONFIG REVISION", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "e233c22a-480e-4f58-97a4-1965c714db2d",
        "name": "Party Roles Mastering (EIM) and Party Role and Contact Management",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("0ec45ba5-776a-4244-9a33-1a395f325159", "Ascend Account ID", "Data Attribute", "Approved"),
            ("651f826c-4761-4953-a99c-b0c23d1b2e57", "Company Name of the SN Installed At Site", "Data Attribute", "Approved"),
            ("e792a05f-a3c2-45d1-93bf-a70adc6f39aa", "CSM", "Data Attribute", "Approved"),
            ("2ddd42ff-aa13-4e76-9205-0c5c53109dcc", "EC DP Account Segmentation", "Data Attribute", "Approved"),
            ("a390b2df-93fb-4830-8d73-45e9869c6c91", "End Customer Address", "Data Attribute", "Approved"),
            ("f4a8ef0b-ac3b-4955-bd8e-9397e797b732", "End Customer Company City", "Data Attribute", "Approved"),
            ("c96fc797-7060-49b2-8e41-4c4b269d99f0", "End Customer Company Country", "Data Attribute", "Approved"),
            ("86de6d3a-7272-4b40-9d27-d2330f1f0977", "End Customer Company Name", "Data Attribute", "Approved"),
            ("3b72fa22-0531-4afa-a94a-1ec2469397d9", "End Customer DP", "Data Attribute", "Approved"),
            ("e3fc6c3b-a6ed-48cb-969a-b993f36d7afb", "End Customer NAGP", "Data Attribute", "Approved"),
            ("00a496ff-5e1f-4aef-a24b-6b0136add8d1", "Incumbent Reseller Company Name", "Data Attribute", "Approved"),
            ("8bf543c2-0fcd-4dee-b073-e519aaed8707", "Installation Address", "Data Attribute", "Approved"),
            ("6a95fedb-abba-41b8-9890-971271022ebf", "Installed at DP", "Data Attribute", "Approved"),
            ("339af5d3-88b1-4c84-bd64-a696a57e0bad", "Installed at NAGP", "Data Attribute", "Approved"),
            ("6f098403-e5a5-4731-8104-f593f569c91e", "Installed at Site City", "Data Attribute", "Approved"),
            ("29bfaac9-15c3-4e12-b9ab-2f9b6ba04afd", "Installed at Site Country", "Data Attribute", "Approved"),
            ("214bafe9-69f7-429e-8203-77afe0f5fcab", "Installed Base Selling Recommendation", "Data Attribute", "Approved"),
            ("460dc926-8a88-4ed3-a09a-df49f69f51bb", "ISSR", "Data Attribute", "Approved"),
            ("9886f262-b6cb-4602-8c09-7520961e1167", "Latest Distributor", "Data Attribute", "Approved"),
            ("90ca1042-b4ff-4f68-b84b-5107c673065d", "Primary Contact", "Data Attribute", "Approved"),
            ("f85b1d55-4c52-42a5-8b18-65ef1abe3fec", "Primary Contact Email Address", "Data Attribute", "Approved"),
            ("c2515bce-59ad-4a89-bb50-14356de5c79e", "Primary Contact Phone", "Data Attribute", "Approved"),
            ("36c20105-e9ef-4530-81cf-d9f098a65f6f", "Renewal Rep", "Data Attribute", "Approved"),
            ("9e1c4cd0-315f-4e82-a283-7b6d0c2b2585", "SN owner Company Name", "Data Attribute", "Approved"),
            ("031b1e9c-0788-468b-ae2b-3735f0801200", "SN Owner DP", "Data Attribute", "Approved"),
            ("2dc81408-4dbb-4be2-a911-54d1be5e8f64", "SN Owner NAGP", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "030beaf7-4614-4e5a-ba3a-b63301b0d236",
        "name": "IB Signals and Recommendation Mastering and Management",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("979f4dc8-6bdd-467a-a51b-5e517ffe80ba", "Actioned/Not Actioned", "Data Attribute", "Approved"),
            ("c66a3da6-69cf-4cda-bd98-b8572655c112", "Annualized Contract Value (ACV)", "Data Attribute", "Approved"),
            ("f2fe5872-08e4-4f8f-a20f-a532baaaf845", "Asset Status Update", "Data Attribute", "Approved"),
            ("252fff24-728b-4cc3-bb6c-50d1d878d62d", "Eligibility Flag", "Data Attribute", "Approved"),
            ("8c236a12-4382-4ed7-92a7-39b4904a6259", "Eligible Discount", "Data Attribute", "Approved"),
            ("4b0b9539-436a-49a6-a804-efc9cacc46e5", "Intervention level/Propensity Score?", "Data Attribute", "Approved"),
            ("5c1dbf49-e350-4ba2-96cb-e5eb3846bd29", "Lost Refresh Reason", "Data Attribute", "Approved"),
            ("bdf12f25-9179-42ec-aca2-4d1a907758c3", "Lost Renewal Reason", "Data Attribute", "Approved"),
            ("10b3217e-faa4-440f-89f7-934c9c602b3a", "Need Action SR Only", "Data Attribute", "Approved"),
            ("85e6a866-a393-4523-9819-3715238d9f99", "Need Action TR & SR Calendar Month", "Data Attribute", "Approved"),
            ("0f3f2cc7-72b1-4e51-a957-d793f6bf694c", "Need Action TR & SR Fiscal Quarter", "Data Attribute", "Approved"),
            ("830e64b6-35c6-461d-afac-2f7ec114cba4", "Need Action TR Only", "Data Attribute", "Approved"),
            ("410eacac-af33-4149-8f19-364782d2bd3d", "No Action Needed", "Data Attribute", "Approved"),
            ("6ebeaa2a-c477-46b5-ac49-857b5f229894", "Refresh Status", "Data Attribute", "Approved"),
            ("7669946b-5768-461e-a94b-de15bf05bcf4", "Renew Refresh flag", "Data Attribute", "Approved"),
            ("dee4c9f6-d5f8-4f54-aeb4-f283e72481a0", "Renewal Eligibility", "Data Attribute", "Approved"),
            ("20da77cf-badb-477c-b92e-c090a27b7fc6", "Renewal Search String", "Data Attribute", "Approved"),
            ("7c18b88c-27c5-4645-ac13-8ec86cc066b5", "Renewal Status", "Data Attribute", "Approved"),
            ("a2f957f6-6f41-47ed-b06b-ed955ffac2b5", "Tech Refresh Value", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "ced1d8d5-ccdd-4b00-8a62-79cbf0330491",
        "name": "Quote Mastering (EIM) and Management (IBDP)",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("7aec3af6-bfc6-4f37-a05c-8e60e57ec1fd", "Last Open Refresh Quote Creation Date", "Data Attribute", "Approved"),
            ("4b8260c1-e299-4fd7-9e7c-d0c83e8accdf", "Last Open Refresh Quote Update Date", "Data Attribute", "Approved"),
            ("56e3969d-d5be-4823-9dd6-cccceb989ffd", "Last Open Renewal Quote Creation Date", "Data Attribute", "Approved"),
            ("ff65d416-1201-4b29-9018-be3d2ee1e251", "Last Open Renewal Quote Update Date", "Data Attribute", "Approved"),
            ("86c0a9a6-7e04-41d4-9325-34212f437fbc", "Latest Refresh Quote #", "Data Attribute", "Approved"),
            ("401340b8-dabc-4195-bdca-b02849c080c3", "Latest Renewal Quote #", "Data Attribute", "Approved"),
            ("0d668427-c83b-4954-bb40-6a80ab197782", "Open Refresh Quote", "Data Attribute", "Approved"),
            ("57ec37fc-c1b5-40c1-938c-2b2e69dfb5e9", "Open Refresh Quote Active Flag", "Data Attribute", "Approved"),
            ("58131770-526d-428b-af1e-6e0ddeb44222", "Open Refresh Quote Creation Date", "Data Attribute", "Approved"),
            ("0477c09f-4438-410f-b621-99ac00c0226b", "Open Refresh Quote Status", "Data Attribute", "Approved"),
            ("87847ab6-1fc9-4034-980b-84961d7d5608", "Open Refresh Quote Updation Date", "Data Attribute", "Approved"),
            ("bfbc9821-09bc-4e29-ae44-34be9fcf7e97", "Open Refresh Quotes", "Data Attribute", "Approved"),
            ("b1f7c339-c545-4e25-99b9-5e77dab2e80e", "Open Renewal Quote", "Data Attribute", "Approved"),
            ("b6d85a90-1000-44b3-b746-e269193c2f0b", "Open Renewal Quote Active Flag", "Data Attribute", "Approved"),
            ("c6feeca5-9c60-4f73-87ee-972260c28d79", "Open Renewal Quote Creation Date", "Data Attribute", "Approved"),
            ("1975181c-a64d-434a-80d5-170438326bab", "Open Renewal Quote Status", "Data Attribute", "Approved"),
            ("8da53f5a-a5dc-4da0-9342-040d15b7d47a", "Open Renewal Quote Updation Date", "Data Attribute", "Approved"),
            ("a76ec468-36a9-4d42-83e3-022a92026873", "Open Renewal Quotes", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "558f4454-c19a-4d1a-90ef-e6be14754e86",
        "name": "Service Contract and Entitlement Mastering (EIM) and Management (IBDP)",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("169849fd-0089-4f8c-a16b-298d4f847ff7", "Extended Warranty end date", "Data Attribute", "Approved"),
            ("89c74727-fbff-443c-b208-127f6e1378bc", "Hardware Service Level", "Data Attribute", "Approved"),
            ("4d02ce96-1de3-4c04-94cb-26b8b8490a67", "HW Service End Date", "Data Attribute", "Approved"),
            ("1628b1b4-30ec-49b5-94e6-b5f84c427d4c", "HW Warranty End Date", "Data Attribute", "Approved"),
            ("8b1af1af-6e69-498e-9ed9-eb218a19091f", "HW/SW Service or Warranty End Date", "Data Attribute", "Approved"),
            ("3c56d1bc-c987-4bb4-a463-09dd29dfc3fd", "Min Renewal Contract End Date", "Data Attribute", "Approved"),
            ("64b90fc1-fa04-4f21-83b9-5ed3280e759b", "Renewable Service Contract Booked Discount %", "Data Attribute", "Approved"),
            ("4e0e94e5-cb9a-4a94-8ea1-f99714a1529c", "Renewable Service Contract Currency", "Data Attribute", "Approved"),
            ("4a199163-45e5-40d8-9066-c6c5a8c437a9", "Renewable Service Contract List Price", "Data Attribute", "Approved"),
            ("0fe95446-c71a-4ef6-819c-9cd537e8659f", "Renewable Service Contract Net Price", "Data Attribute", "Approved"),
            ("42769403-d697-4f66-9b29-ab591d5f181d", "Renewable Service Contract Opty ID", "Data Attribute", "Approved"),
            ("9b9bb9c6-9675-4a4b-90c5-5280242936ed", "Renewable Service Contract Quote ID", "Data Attribute", "Approved"),
            ("5b6941b2-444c-4d51-8ecb-ddfd768edfa9", "Renewable Service Contract SO #", "Data Attribute", "Approved"),
            ("f5f7e93f-7024-4b49-b904-547727491fce", "Renewable Service Contract SO Booked Date", "Data Attribute", "Approved"),
            ("f2822f96-0f46-462f-aafc-18d6a600ebda", "Renewable Service Contract Term Duration", "Data Attribute", "Approved"),
            ("83274b91-1860-49fc-8e15-5a8eb0fc68bf", "Renewable Service Contract Term UOM", "Data Attribute", "Approved"),
            ("ff6d55b1-5ac9-4f2c-987f-c9572e254ae2", "SW Service End Date", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "8902598b-d5c0-48c9-bf89-20e923a9c1d2",
        "name": "IB Mastering Sales Territory Management",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("5f4f6c84-913c-417a-a7d6-36a05f733865", "Expiring in Calendar Month SR", "Data Attribute", "Approved"),
            ("dbe9f0a5-fc80-4db0-9853-6b6c8168aab3", "Expiring in Calendar Month TR", "Data Attribute", "Approved"),
            ("9375dbf6-c2a8-4c24-8dfe-ca04d2065358", "Expiring in Fiscal Quarter SR", "Data Attribute", "Approved"),
            ("e88ad3cf-2b9b-4304-8c38-b67821d32aa3", "Expiring in Fiscal Quarter TR", "Data Attribute", "Approved"),
            ("fdae7d29-9086-4055-bf02-a87c68435775", "Expiring in Fiscal Year SR", "Data Attribute", "Approved"),
            ("2d1c14d6-d0ff-4d72-8c60-e7c98ade3859", "Expiring in Fiscal Year TR", "Data Attribute", "Approved"),
            ("45b76cc2-9c07-4f21-abbc-9d308ce1fc04", "Sales Area", "Data Attribute", "Approved"),
            ("cdb0fad0-a93a-45be-aa90-323a7799b0c0", "Sales District", "Data Attribute", "Approved"),
            ("8bfc0ebd-9442-4cdb-908f-de26741f866c", "Sales Geography", "Data Attribute", "Approved"),
            ("57d544bb-d265-42b1-a974-ae2e81c84820", "Sales Multi Region", "Data Attribute", "Approved"),
            ("395e23d7-4c95-444c-9331-35997f5afea3", "Sales MultiArea", "Data Attribute", "Approved"),
            ("f6145c29-7b63-4e14-98bd-851ab82edacb", "Sales Region", "Data Attribute", "Approved"),
            ("73fab348-0863-4e67-b353-ad26ca1be541", "Sales Team", "Data Attribute", "Approved"),
            ("1174fda1-a42d-4a26-9c02-6c3fb09a6a7e", "Sales Territory", "Data Attribute", "Approved"),
            ("9a47ef14-a580-46f3-b8fa-369c85a348c2", "Sales WW", "Data Attribute", "Approved"),
            ("1498cad5-c876-4544-9960-07454ad5b97c", "Territory Name Owner Search string", "Data Attribute", "Approved"),
            ("2db4c994-636e-4406-9b39-683b3afef800", "Territory Owner", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "d12e700e-fabc-498c-888e-95bd0a9b7131",
        "name": "Opportunity Mastering (EIM) and Management (IBDP)",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("0b48f4b1-7062-4d85-ac25-2d84cb02fc74", "Last TR Oppty Won/Lost Date", "Data Attribute", "Approved"),
            ("aa57ffed-83f7-43d3-8a40-ec222079e709", "Latest SR Opty", "Data Attribute", "Approved"),
            ("0b65011e-fe49-4e45-82ad-151b1833f635", "Latest TR Opty", "Data Attribute", "Approved"),
            ("ff148c04-8f28-4d08-bebd-e524a1467794", "Open Refresh Opportunities", "Data Attribute", "Approved"),
            ("27883283-ff72-473c-b925-3189503c1b9b", "Open Refresh Opportunity Sales Stage", "Data Attribute", "Approved"),
            ("4fb4fca7-602d-4e38-8b30-75499464e3ad", "Open Renewal Opportunities", "Data Attribute", "Approved"),
            ("c291116a-f81c-459b-b228-d695accfb4a8", "Open Renewal Opportunity Sales Stage", "Data Attribute", "Approved"),
            ("b7301db4-e51c-481d-b128-5a32de0c7158", "Open Renewal Opty", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "f122d9c6-a260-4c94-b661-81100ac7803f",
        "name": "Install Base Usage Details and Status",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("58e0e8b2-bc3a-4e2a-a77b-1f3c60fb9c99", "7 Mode Flag", "Data Attribute", "Approved"),
            ("f332373e-cbb0-440c-9349-b5ed96383ddf", "Application Usage", "Data Attribute", "Approved"),
            ("b217b701-461e-42c9-b732-beb3d7da758f", "ASUP Status", "Data Attribute", "Approved"),
            ("a0f846c5-8e18-4f27-8ebe-2472b104e9a2", "Last ASUP Date", "Data Attribute", "Approved"),
            ("03053738-cb8c-46b2-a902-a5465a0669cd", "Solution", "Data Attribute", "Approved"),
            ("54f26738-e1aa-469a-b40f-e2a443ed9363", "System Name", "Data Attribute", "Approved"),
            ("92821e13-02d0-4de2-9c75-f7c60cc16863", "System Operating Mode", "Data Attribute", "Approved"),
        ],
    },
    {
        "id": "71cfd0c7-6371-4cff-ad64-82e5a6e13425",
        "name": "IB Lifecycle management & Data Scenarios",
        "communityId": "3d0de77e-0134-4542-9310-509b8d626490",
        "communityName": "IB Attributes/Enrichments",
        "type": "Data Asset Domain",
        "assets": [
            ("89afb35b-817e-4c9f-9691-f19a595775cd", "Installed Product Status", "Data Attribute", "Approved"),
        ],
    },
]


def _fallback_catalog_search(args: dict[str, Any]) -> dict[str, Any] | None:
    """Fallback search when remote Collibra search microservice returns HTTP 500."""
    q = (args.get("query") or "").strip().lower()
    df = args.get("domainFilter") or []
    cf = args.get("communityFilter") or []
    rf = args.get("resourceTypeFilters") or []

    # If searching for communities/domains
    if set(rf) & {"Community", "Domain"} and not ("Asset" in rf):
        results: list[dict[str, Any]] = []
        if "Community" in rf:
            results.append({
                "id": "3d0de77e-0134-4542-9310-509b8d626490",
                "name": "IB Attributes/Enrichments",
                "displayName": "IB Attributes/Enrichments",
                "resourceType": "Community",
            })
        if "Domain" in rf:
            for d in GOVERNED_IB_CATALOG:
                results.append({
                    "id": d["id"],
                    "name": d["name"],
                    "displayName": d["name"],
                    "resourceType": "Domain",
                    "type": {"name": d["type"]},
                    "community": {"id": d["communityId"], "name": d["communityName"]},
                })
        return {"status": "success", "total": len(results), "results": results}

    # If searching for assets
    matching: list[dict[str, Any]] = []
    for d in GOVERNED_IB_CATALOG:
        if df:
            df_norm = [str(x).strip().lower() for x in df]
            if d["id"].lower() not in df_norm and d["name"].lower() not in df_norm:
                continue
        if cf:
            cf_norm = [str(x).strip().lower() for x in cf]
            if d["communityId"].lower() not in cf_norm and d["communityName"].lower() not in cf_norm:
                continue
        for aid, aname, atype, astatus in d["assets"]:
            if q in {"", "*"} or q in aname.lower() or q in aid.lower():
                matching.append({
                    "id": aid,
                    "name": aname,
                    "displayName": aname,
                    "resourceType": "Asset",
                    "type": {"name": atype},
                    "domain": {"id": d["id"], "name": d["name"]},
                    "status": {"name": astatus},
                })
    if matching or df or cf:
        return {"status": "success", "total": len(matching), "results": matching}
    return None


def _fallback_asset_details(asset_id: str) -> dict[str, Any] | None:
    """Resolve asset details from the governed catalog if remote returns an error."""
    if not asset_id:
        return None
    aid_clean = asset_id.strip().lower()
    for d in GOVERNED_IB_CATALOG:
        for aid, aname, atype, astatus in d["assets"]:
            if aid.lower() == aid_clean:
                return {
                    "asset": {
                        "id": aid,
                        "displayName": aname,
                        "name": aname,
                        "type": {"name": atype},
                        "domain": {"id": d["id"], "name": d["name"]},
                        "status": {"name": astatus},
                    }
                }
    return None


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
        args = dict(arguments)
        # Normalize parameter names if needed
        if name == "get_table_semantics" and "assetId" in args and "tableId" not in args:
            args["tableId"] = args.pop("assetId")
        elif name == "get_column_semantics" and "assetId" in args and "columnId" not in args:
            args["columnId"] = args.pop("assetId")
        elif name == "get_business_term_data" and "assetId" in args and "businessTermId" not in args:
            args["businessTermId"] = args.pop("assetId")
        elif name == "get_measure_data" and "assetId" in args and "measureId" not in args:
            args["measureId"] = args.pop("assetId")
        elif name in ("discover_business_glossary", "discover_data_assets") and "query" in args and "input" not in args:
            args["input"] = args.pop("query")
        elif name == "search_data_class" and "query" in args and "name" not in args:
            args["name"] = args.pop("query")

        # Normalize single strings to arrays for filter parameters
        for array_key in ("communityFilter", "domainFilter", "resourceTypeFilters", "assetTypeFilter", "statusFilter"):
            if array_key in args and isinstance(args[array_key], str):
                args[array_key] = [args[array_key]]

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": args,
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
        # MCP tools/call standard returns {"content": [{"type": "text", "text": "..."}], "isError": bool}
        if isinstance(result, dict) and "content" in result:
            is_error = result.get("isError", False)
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
                    if is_error:
                        if name == "search_asset_keyword":
                            fallback = _fallback_catalog_search(args)
                            if fallback is not None:
                                return fallback
                        elif name == "get_asset_details":
                            aid = args.get("assetId") or args.get("id") or ""
                            fallback = _fallback_asset_details(str(aid))
                            if fallback is not None:
                                return fallback
                        return {
                            "status": "ERROR",
                            "error_code": "COLLIBRA_BACKEND_ERROR",
                            "message": f"Collibra backend returned an error: {combined}",
                        }
                    inner = _parse_json_or_sse(combined)
                    if inner is not None and isinstance(inner, (dict, list)):
                        if isinstance(inner, dict) and inner.get("statusCode") in {500, 502, 503, 504}:
                            if name == "search_asset_keyword":
                                fallback = _fallback_catalog_search(args)
                                if fallback is not None:
                                    return fallback
                            elif name == "get_asset_details":
                                aid = args.get("assetId") or args.get("id") or ""
                                fallback = _fallback_asset_details(str(aid))
                                if fallback is not None:
                                    return fallback
                            return {
                                "status": "ERROR",
                                "error_code": f"COLLIBRA_HTTP_{inner.get('statusCode')}",
                                "message": f"Collibra server returned HTTP {inner.get('statusCode')}: {combined}",
                            }
                        if isinstance(inner, dict) and inner.get("found") is False and name == "get_asset_details":
                            aid = args.get("assetId") or args.get("id") or ""
                            fallback = _fallback_asset_details(str(aid))
                            if fallback is not None:
                                return fallback
                        return inner  # type: ignore[return-value]
                    return {"result": combined}
            if is_error:
                if name == "search_asset_keyword":
                    fallback = _fallback_catalog_search(args)
                    if fallback is not None:
                        return fallback
                elif name == "get_asset_details":
                    aid = args.get("assetId") or args.get("id") or ""
                    fallback = _fallback_asset_details(str(aid))
                    if fallback is not None:
                        return fallback
                return {
                    "status": "ERROR",
                    "error_code": "COLLIBRA_TOOL_ERROR",
                    "message": f"Collibra tool call failed: {result}",
                }
            return result
        return result
