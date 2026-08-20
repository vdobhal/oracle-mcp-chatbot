"""Throwaway: exercise the real On-Prem tools end to end."""
import json
from pathlib import Path

from oracle_mcp.audit import AuditLogger
from oracle_mcp.db import ConnectionRegistry
from oracle_mcp.policy import get_policy_store
from oracle_mcp.settings import get_settings
from oracle_mcp.tools import ToolService

settings = get_settings()
# oracle_profiles is keyed by profile name ("onprem"), not database name.
profiles = {
    n: p for n, p in settings.oracle_profiles.items() if p.database_name.upper() == "ONPREM"
}
if not profiles:
    raise SystemExit(
        "No ONPREM profile found. Check ONPREM_ENABLED and the ONPREM_* values in .env."
    )
store = get_policy_store(settings.policy_dir, {"ONPREM": "onprem.yaml"})
registry = ConnectionRegistry(profiles, query_timeout_seconds=settings.query_timeout_seconds)
svc = ToolService(
    settings=settings,
    store=store,
    registry=registry,
    audit=AuditLogger(sink="file", file_path=Path("logs/probe.jsonl")),
)

print("=== list_allowed_tables(EIM) ===")
r = svc.list_allowed_tables("ONPREM", "EIM", "analyst")
for o in r.get("objects", []):
    print(f"  {o['table_name']:<28} rows≈{o.get('estimated_row_count')}")

for table in ("EIM_PR_ROLES", "EIM_PR_SYSTEM"):
    print(f"\n=== get_table_metadata({table}) ===")
    m = svc.get_table_metadata("ONPREM", "EIM", table, "analyst")
    if m.get("status") != "OK":
        print("  ", json.dumps(m)[:400])
        continue
    cols = m.get("columns", [])
    print(f"  {len(cols)} columns visible; first 12:")
    for c in cols[:12]:
        print(f"    {c['column_name']:<30} {c.get('data_type')}")
    if m.get("restricted_columns"):
        print("  restricted:", m["restricted_columns"])

print("\n=== validate + execute a real query ===")
v = svc.validate_sql("ONPREM", "SELECT COUNT(*) AS role_count FROM eim.eim_pr_roles", "analyst")
print("  validation:", v.get("validation_status"), [e["code"] for e in v.get("validation_errors", [])])
if v.get("validation_status") == "APPROVED":
    e = svc.execute_readonly_sql("ONPREM", v["rewritten_safe_sql"], "analyst")
    print("  status:", e.get("status"))
    print("  rows  :", e.get("rows"))
    if e.get("status") != "OK":
        print("  error :", json.dumps({k: val for k, val in e.items() if k != "rows"})[:600])

registry.close_all()
