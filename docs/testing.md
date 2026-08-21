# How to test the chatbot

Four ways to exercise a running deployment, loosest to strictest. Every command
here was run against the live databases and reproduced verbatim.

This is the operator's guide. For what the automated suite covers and why, see
[testing-scenarios.md](testing-scenarios.md).

All commands assume the project root and the local dependency directory:

```bash
cd oracle-mcp-chatbot
export PYTHONPATH=.pydeps:src
```

---

## 1. Is it alive?

Validates credentials, TLS and policy load without reading a row.

```bash
python3 -m oracle_mcp.server --profile atp --check
python3 -m oracle_mcp.server --profile onprem --check
```

```
ATP: OK
ATP: discovery mode over NAPPERP, NAPPERPADM, NAPPERPDS
ATP: 9 object exclusion(s)
ATP: domains Install Base, Service Contract, Product, Customer, EIM Integration
roles: admin, analyst, architect, business_user, support
```

`OK` means the pool opened and a round trip succeeded. Run this first: it
separates "the database is unreachable" from "the chatbot refused", which look
identical from a chat window.

The two databases report differently on purpose. On-Prem prints
`1 schema(s), 5 approved object(s)` because it declares its objects; ATP prints
its discovery scope because it declares none.

---

## 2. Ask it questions in plain English

The closest thing to how an end user experiences the system, and the only path
that tests the agent's judgement rather than just the plumbing.

Both servers are registered in `.cursor/mcp.json`, so a Cursor chat calls the
tools itself. Restart Cursor after changing policy or server code — MCP servers
are launched once per session.

Nine tools are exposed: `list_allowed_schemas`, `list_allowed_tables`,
`get_table_metadata`, `search_data_dictionary`, `validate_sql`,
`execute_readonly_sql`, `explain_query_result`, and
`compare_onprem_and_atp_data` when both profiles are enabled.

Questions that exercise real data:

| Ask | Should reach |
|---|---|
| What customer information is available in ATP? | `HZ_PARTIES`, `NAPP_CX_*EXTRACTPVO` |
| Show me all party roles | On-Prem `EIM_PR_ROLES` |
| How many systems are decommissioned? | On-Prem `EIM_PR_SYSTEM` |
| What tables hold service contract data? | `NAPP_SM_*`, `NAPP_CX_CONTRACT*` |

Then confirm it declines the things it should. Ask it to delete rows, or to
query `GTM_CDM_MISMATCH_DUMP_22MAY`. A correct answer is a refusal with a reason,
not an apology followed by compliance.

Watch for two failure modes that only appear in conversation:

- **Answering from memory.** If a reply contains figures without a
  `Data Source Used` section, the model answered from context rather than the
  database. Ask "which table did that come from?"
- **Choosing a stale twin.** `HZ_PARTY_USG_ASSIGNMENTS` (view, live) and
  `NAPP_CX_HZ_PARTY_USG_ASSIGNMENTS` (table, extract snapshot) hold the same
  data at different freshness. Picking on name similarity is silently wrong.

---

## 3. Run one question through the real tool chain

`scripts/ask.py` goes through `validate_sql` then `execute_readonly_sql`, so the
guardrails, row cap and masking apply exactly as in a chat session. Anything
refused here is refused in the chatbot, for the same reason.

```bash
python3 scripts/ask.py "<sql>" [role] [database]
```

`role` defaults to `analyst`, `database` to `ONPREM`.

A query that should work:

```bash
python3 scripts/ask.py \
  "SELECT party_id, party_name, party_type FROM napperpds.hz_parties" analyst ATP
```

```
database   : ATP
validation : APPROVED  role=analyst
  warn: A row limit of 500 was applied automatically.
executed   : SELECT ... FETCH FIRST 500 ROWS ONLY

3 row(s), 3 column(s)
```

### Confirm the guardrails bite

More important than the happy path. Each of these must be rejected at
validation, before the database is touched:

```bash
# write -> NOT_A_SELECT
python3 scripts/ask.py "DELETE FROM napperpds.hz_parties" analyst ATP

# excluded object -> OBJECT_NOT_ALLOWLISTED
python3 scripts/ask.py "SELECT * FROM napperp.gtm_cdm_mismatch_dump_22may" analyst ATP

# schema outside the scope -> OBJECT_NOT_ALLOWLISTED
python3 scripts/ask.py "SELECT * FROM apex_240200.wwv_flow_app" analyst ATP

# DDL -> NOT_A_SELECT
python3 scripts/ask.py "DROP TABLE napperpds.hz_parties" analyst ATP
```

```
database   : ATP
validation : REJECTED  role=analyst
  ERROR OBJECT_NOT_ALLOWLISTED: NAPPERP.GTM_CDM_MISMATCH_DUMP_22MAY is not an
  approved object on Oracle ATP.
```

Rejection wording is deliberately identical for "does not exist" and "you may
not see it". Telling a caller which one applies is itself a schema disclosure.

Swap `analyst` for `business_user` to watch clearance narrow the result, and for
`admin` to see the widest view. The role is pinned by environment in deployment
(`ORACLE_MCP_ROLE_BINDING_MODE=env`) precisely so a caller cannot choose it.

---

## 4. The automated suite

215 tests, no Oracle instance required — the driver and data dictionary are
faked, so the guardrail, masking, RBAC, discovery and audit paths run
deterministically in a few seconds.

```bash
.pydeps/bin/pytest -q                   # all 215
.pydeps/bin/pytest -q -m security       # the 166 that assert a control
.pydeps/bin/pytest -q tests/test_sql_guard.py
```

Run this before any policy change ships. It is the only check that runs without
credentials, so it is also the one that works in CI.

---

## 5. Standalone browser UI (not Cursor)

Same Oracle tools as the MCP server, in a browser. Requires `ORACLE_MCP_LLM_API_KEY`.
See [chat-ui.md](chat-ui.md).

```bash
python3 -m oracle_mcp.chat --profile both
# open http://127.0.0.1:8500
```

---

## Reading the audit trail

Every call is written as a JSON line, including the refusals — a rejected query
is a security event and is logged as one.

```bash
tail -5 logs/audit-atp.jsonl | python3 -m json.tool
```

| Tool | Status | Rows | Time |
|---|---|---|---|
| `validate_sql` | SUCCESS | 0 | 0 ms |
| `execute_readonly_sql` | SUCCESS | 3 | 541 ms |
| `validate_sql` | REJECTED | 0 | 0 ms |

Records carry the user id, role, tool, status, row count, elapsed time and a
SHA-256 of the SQL. They never carry credentials or result values.

`scripts/ask.py` writes to `logs/ask.jsonl`; the MCP servers write to
`logs/audit-onprem.jsonl` and `logs/audit-atp.jsonl`. All of `logs/` is
gitignored.

---

## When something looks wrong

| Symptom | Likely cause |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` on ATP | `SSL_CERT_FILE` unset; see [environment-configuration.md](environment-configuration.md) |
| `0 schema(s), 0 approved object(s)` | Old build. Discovery mode now reports its scope instead |
| Tool absent from the chat client | Cursor not restarted since `mcp.json` or server changed |
| `compare_onprem_and_atp_data` missing | Only registered when both profiles are enabled in one process |
| Object exists in SQL Developer but not here | Excluded by `excluded_objects`, or its schema is outside `discovered_schemas` |
| Chat answers without `Data Source Used` | Answered from context, not the database. Re-ask naming the table |
