"""Column inventory for the allowlisted On-Prem objects.

Reads column names only, no row data. Prints what the masking rules classify as
sensitive, and flags names that look sensitive but currently classify as
INTERNAL so they can be reviewed rather than discovered in production.
"""
import re
from pathlib import Path

from oracle_mcp.db import ConnectionRegistry
from oracle_mcp.masking import Masker
from oracle_mcp.policy import get_policy_store
from oracle_mcp.settings import get_settings

# Words that often indicate personal, contact, location or credential data but
# are not covered by the current patterns in config/policy/masking.yaml.
SUSPECT = re.compile(
    r"(?i)(mac_addr|ip_addr|ipaddr|hostname|domain|location|city|state|country|region|"
    r"postal|zip|addr|contact|customer|owner|user_name|username|login|account|"
    r"latitude|longitude|geo|site|company|org_name|partner|reseller|end_user|"
    r"serial|snmp|license|key|cert)"
)

settings = get_settings()
profiles = {
    n: p for n, p in settings.oracle_profiles.items() if p.database_name.upper() == "ONPREM"
}
store = get_policy_store(settings.policy_dir, {"ONPREM": "onprem.yaml"})
masker = Masker(store.masking_config)
registry = ConnectionRegistry(profiles, query_timeout_seconds=settings.query_timeout_seconds)
conn = registry.get("ONPREM")

SQL = """
    SELECT column_name, data_type
      FROM all_tab_columns
     WHERE owner = :owner AND table_name = :table_name
     ORDER BY column_id
"""

for obj in store.database("ONPREM").iter_objects():
    _, rows, _, _ = conn.fetch(SQL, {"owner": obj.schema, "table_name": obj.name}, max_rows=2000)
    classified: list[tuple[str, str]] = []
    suspect: list[str] = []
    for r in rows:
        name = r["COLUMN_NAME"]
        level = masker.infer_sensitivity(name)
        if level != "INTERNAL":
            classified.append((name, level))
        elif SUSPECT.search(name):
            suspect.append(name)

    print(f"\n{'=' * 70}\n{obj.fqn}  ({len(rows)} columns)\n{'=' * 70}")
    print(f"  Classified above INTERNAL by masking.yaml: {len(classified)}")
    for name, level in classified:
        print(f"    {level:<13} {name}")
    print(f"  Look sensitive but classify INTERNAL: {len(suspect)}")
    for name in suspect:
        print(f"    review        {name}")

registry.close_all()
