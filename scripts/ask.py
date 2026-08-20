"""Run one question through the full tool chain, the way the MCP client would.

Usage:
    PYTHONPATH=.pydeps:src python3 scripts/ask.py "SELECT ..." [role] [database]

    database defaults to ONPREM; pass ATP to hit the ERP schemas.
    role defaults to analyst; try business_user to watch clearance bite.

Goes through validate_sql then execute_readonly_sql, so the guardrails, row cap
and masking all apply exactly as they would in a chat session. A query that is
refused here is refused in the chatbot, for the same reason.
"""
import sys
from pathlib import Path

from oracle_mcp.audit import AuditLogger
from oracle_mcp.db import ConnectionRegistry
from oracle_mcp.policy import get_policy_store
from oracle_mcp.settings import get_settings
from oracle_mcp.tools import ToolService

DEFAULT_SQL = {
    "ONPREM": "SELECT * FROM eim.eim_pr_roles",
    "ATP": "SELECT * FROM napperpds.hz_parties",
}

sql = sys.argv[1] if len(sys.argv) > 1 else ""
role = sys.argv[2] if len(sys.argv) > 2 else "analyst"
database = (sys.argv[3] if len(sys.argv) > 3 else "ONPREM").upper()
if database not in DEFAULT_SQL:
    raise SystemExit(f"Unknown database {database!r}; expected ONPREM or ATP.")
sql = sql or DEFAULT_SQL[database]

settings = get_settings()
profiles = {
    n: p for n, p in settings.oracle_profiles.items() if p.database_name.upper() == database
}
if not profiles:
    raise SystemExit(
        f"No {database} profile is enabled. Set {database}_ENABLED=true in .env."
    )
store = get_policy_store(settings.policy_dir, {database: f"{database.lower()}.yaml"})
registry = ConnectionRegistry(profiles, query_timeout_seconds=settings.query_timeout_seconds)
svc = ToolService(
    settings=settings,
    store=store,
    registry=registry,
    audit=AuditLogger(sink="file", file_path=Path("logs/ask.jsonl")),
)

v = svc.validate_sql(database, sql, role)
print(f"database   : {database}")
print(f"validation : {v.get('validation_status')}  role={role}")
for e in v.get("validation_errors", []):
    print(f"  ERROR {e['code']}: {e['message']}")
for w in v.get("warnings", []):
    print(f"  warn: {w}")

if v.get("validation_status") == "APPROVED":
    print(f"executed   : {v.get('rewritten_safe_sql')}\n")
    r = svc.execute_readonly_sql(database, v["rewritten_safe_sql"], role)
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
