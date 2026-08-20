"""Run one question through the full tool chain, the way the MCP client would.

Usage:
    PYTHONPATH=.pydeps:src python3 scripts/ask.py "SELECT ..." [role]

Goes through validate_sql then execute_readonly_sql, so the guardrails, row cap
and masking all apply exactly as they would in a chat session.
"""
import sys
from pathlib import Path

from oracle_mcp.audit import AuditLogger
from oracle_mcp.db import ConnectionRegistry
from oracle_mcp.policy import get_policy_store
from oracle_mcp.settings import get_settings
from oracle_mcp.tools import ToolService

sql = sys.argv[1] if len(sys.argv) > 1 else "SELECT * FROM eim.eim_pr_roles"
role = sys.argv[2] if len(sys.argv) > 2 else "analyst"

settings = get_settings()
profiles = {
    n: p for n, p in settings.oracle_profiles.items() if p.database_name.upper() == "ONPREM"
}
store = get_policy_store(settings.policy_dir, {"ONPREM": "onprem.yaml"})
registry = ConnectionRegistry(profiles, query_timeout_seconds=settings.query_timeout_seconds)
svc = ToolService(
    settings=settings,
    store=store,
    registry=registry,
    audit=AuditLogger(sink="file", file_path=Path("logs/ask.jsonl")),
)

v = svc.validate_sql("ONPREM", sql, role)
print(f"validation : {v.get('validation_status')}  role={role}")
for e in v.get("validation_errors", []):
    print(f"  ERROR {e['code']}: {e['message']}")
for w in v.get("warnings", []):
    print(f"  warn: {w}")

if v.get("validation_status") == "APPROVED":
    print(f"executed   : {v.get('rewritten_safe_sql')}\n")
    r = svc.execute_readonly_sql("ONPREM", v["rewritten_safe_sql"], role)
    if r.get("status") != "OK":
        print("FAILED:", r.get("message") or r)
    else:
        rows = r.get("rows", [])
        cols = r.get("columns", [])
        print(f"{r.get('row_count')} row(s), {len(cols)} column(s)")
        if r.get("masked_columns"):
            print("masked:", r["masked_columns"])
        widths = {
            c: max(len(str(c)), *(len(str(row.get(c, ""))) for row in rows)) if rows else len(c)
            for c in cols
        }
        print("\n" + " | ".join(str(c).ljust(widths[c]) for c in cols))
        print("-+-".join("-" * widths[c] for c in cols))
        for row in rows:
            print(" | ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols))

registry.close_all()
