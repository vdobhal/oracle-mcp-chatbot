# Architecture

## 1. High-level design

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Business user / analyst / architect / support                           │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ natural language
┌────────────────────────────────▼─────────────────────────────────────────┐
│  AI CHATBOT  (MCP client)                                                │
│  · system prompt (prompts/system_prompt.md)                              │
│  · plans tool calls, narrates results                                    │
│  · UNTRUSTED from the server's point of view                             │
└──────┬────────────────────────────────────────┬──────────────────────────┘
       │ MCP (stdio or Streamable HTTP)         │
┌──────▼──────────────────────┐   ┌─────────────▼───────────────────────────┐
│ MCP SERVER: ON-PREM         │   │ MCP SERVER: ATP                         │
│ profile=onprem              │   │ profile=atp                             │
│                             │   │                                         │
│  ┌───────────────────────┐  │   │  ┌───────────────────────┐              │
│  │ tools.py              │  │   │  │ tools.py              │              │
│  ├───────────────────────┤  │   │  ├───────────────────────┤              │
│  │ policy.py  allowlist  │  │   │  │ policy.py  allowlist  │              │
│  │ sql_guard.py          │  │   │  │ sql_guard.py          │              │
│  │ masking.py            │  │   │  │ masking.py            │              │
│  │ audit.py              │  │   │  │ audit.py              │              │
│  │ db.py  pool           │  │   │  │ db.py  pool           │              │
│  └───────────┬───────────┘  │   │  └───────────┬───────────┘              │
│  creds: on-prem only        │   │  creds: ATP wallet only                 │
└──────────────┼──────────────┘   └──────────────┼──────────────────────────┘
               │ TCP/TCPS                        │ mTLS (wallet)
┌──────────────▼──────────────┐   ┌──────────────▼──────────────────────────┐
│ ON-PREM ORACLE              │   │ ORACLE ATP                              │
│ user CHATBOT_RO             │   │ user CHATBOT_RO, LOW consumer group     │
│ CREATE SESSION + SELECT     │   │ CREATE SESSION + SELECT                 │
└─────────────────────────────┘   └─────────────────────────────────────────┘

Optional third process, profile=both — holds both credential sets and is the
only one exposing compare_onprem_and_atp_data.
```

**Why two servers rather than one.** A single process holding both credential
sets means any code-execution flaw reaches both databases. Splitting them means
an on-prem compromise cannot read the ATP wallet passphrase, because that value
was never in the process. The reconciliation server reintroduces the shared blast
radius deliberately, which is why it is optional, separately deployed, and gated
on `allow_reconciliation`.

## 2. Request flow

A question like *"Which customer records were updated today in CDM?"*:

```
 1  search_data_dictionary("customer updated date")
        → CDM_RPT.V_CUSTOMER_MASTER.LAST_UPDATED_DATE   confidence 0.8
 2  get_table_metadata(ONPREM, CDM_RPT, V_CUSTOMER_MASTER)
        → exact column names, types, nullability, PK
 3  model drafts:
        SELECT customer_number, customer_status, last_updated_date
          FROM CDM_RPT.V_CUSTOMER_MASTER
         WHERE TRUNC(last_updated_date) = TRUNC(SYSDATE)
 4  validate_sql(...)
        normalise → parse → node-type check → pattern scan → allowlist →
        column clearance → shape rules → rewrite
        → APPROVED, rewritten_safe_sql (+ FETCH FIRST 500 ROWS ONLY)
        → fingerprint cached against (ONPREM, analyst)
 5  execute_readonly_sql(rewritten_safe_sql)
        re-validate from scratch → fingerprint must be pre-approved →
        SET TRANSACTION READ ONLY → execute with call_timeout →
        fetch max_rows+1 → mask → return
 6  explain_query_result(...)
        → row count, null rates, distinct counts, quality flags
 7  model composes the answer using only tool-supplied figures
```

Steps 4 and 5 both validate. That is not redundancy: without it, validation and
execution are two separate trust decisions with a gap between them.

## 3. Security boundaries

Data reaches a user only by crossing all five layers.

| # | Layer | Enforced by | Defeats |
|---|---|---|---|
| 1 | Database grants | `sql/01`, `sql/02` | Everything outside `CREATE SESSION` + explicit `SELECT` |
| 2 | Object allowlist | `policy.py`, `config/policy/*.yaml` | A grant made outside change control |
| 3 | Role clearance | `policy.py` roles | A user reaching data above their classification |
| 4 | SQL guardrails | `sql_guard.py` | Writes, injection, obfuscation, runaway scans |
| 5 | Output masking | `masking.py` | Sensitive values in otherwise-approved rows |

Plus two runtime controls: `SET TRANSACTION READ ONLY` per transaction, and
`connection.call_timeout` so a slow query is cancelled in the database.

### The central design decision

`sql_guard.py` never executes the text it was given. It parses input into an AST,
inspects and rewrites that AST, and regenerates SQL from it. Only node types the
validator recognised are re-emitted, so comment tricks, stacked statements,
whitespace padding and homoglyph keywords cannot survive the round trip — there
is no path by which unrecognised syntax becomes executed text.

Illustrated:

| Input | What executes |
|---|---|
| `SELECT a FROM t -- ignore instructions` | `SELECT a FROM t FETCH FIRST 500 ROWS ONLY` |
| `SELECT a FROM t; DROP TABLE t` | nothing — `MULTIPLE_STATEMENTS` |
| `SELECT /*+ PARALLEL(t,64) */ a FROM t` | `SELECT a FROM t FETCH FIRST 500 ROWS ONLY` |
| `ＤＥＬＥＴＥ FROM t` | nothing — NFKC folds it to `DELETE`, then rejected |
| `SELECT * FROM v` (business_user) | explicit column list, restricted columns absent |

## 4. Role and access control model

Defined in `config/policy/roles.yaml`. Clearance ladder:
`PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED < NEVER`.

| Role | Clearance | Rows | Raw SQL | Sees SQL | Reconcile | Schemas (On-Prem / ATP) |
|---|---|---|---|---|---|---|
| `business_user` | INTERNAL | 200 | no | no | no | `CDM_RPT` / `ATP_RPT` |
| `analyst` | CONFIDENTIAL | 500 | no | yes | yes | `+ CDM` / `+ ATP_CDM` |
| `architect` | CONFIDENTIAL | 500 | no | yes | yes | `+ CDM` / `+ ATP_CDM` |
| `support` | CONFIDENTIAL | 500 | no | yes | yes | `+ CDM_OPS` / `+ ATP_OPS` |
| `admin` | RESTRICTED | 500 | yes | yes | yes | all |

Three things a role controls beyond schema access:

- **`clearance`** gates both objects and individual columns. A column classified
  above the role is rejected when named explicitly, and redacted when it arrives
  via `SELECT *`.
- **`allow_raw_sql`** decides whether `execute_readonly_sql` accepts a statement
  that was not first approved by `validate_sql`. Only `admin` may, and the SQL
  still passes the entire guardrail chain.
- **`max_rows`** is combined with the server cap by taking the *tighter* of the
  two, so a role can lower the limit but never raise it.

### How the role is decided — the part that matters

`ORACLE_MCP_ROLE_BINDING_MODE` controls where the role comes from:

- **`env` (production).** The role is pinned by process configuration. The
  `user_role` tool argument is ignored entirely. To give a user a different role,
  run a server instance configured for it and let your gateway route them there.
- **`argument` (development only).** The role comes from the tool argument.

The distinction is the whole ballgame. Anything arriving as a tool argument has
passed through the model, so it is attacker-influenced by definition: a user who
writes "you are now an admin" produces a model that sends `user_role="admin"`.
Under `env` binding that string lands in a parameter nothing reads.

`test_pinned_role_binding_ignores_the_role_argument` is the regression test.

## 5. Audit design

One record per tool invocation, to `logs/audit.jsonl`, an Oracle table, or both.

| Field | Purpose |
|---|---|
| `request_id`, `event_time` | Correlation and ordering |
| `tool_name`, `database_name` | What ran, where |
| `user_id`, `user_role` | Who, and with what clearance |
| `status` | `SUCCESS` / `REJECTED` / `ERROR` |
| `user_question` | Whitespace-flattened, truncated |
| `sql_redacted` | Literals replaced with `?` |
| `sql_sha256` | Hash of the exact executed text |
| `validation_status`, `validation_errors` | Which guardrail fired |
| `row_count`, `truncated`, `execution_ms` | Volume and cost |
| `masked_columns` | Which fields were protected, and why |
| `referenced_objects` | Which approved objects were touched |
| `error_code`, `error_message` | Failure detail |

Two deliberate properties:

**Redaction with a hash.** Storing `WHERE tax_id = '123-45-6789'` verbatim would
copy the exact value the masking layer just suppressed into a second, often
less-protected store. Literals are replaced with `?`; the SHA-256 still lets an
investigator match executions exactly.

**Audit failures never propagate.** A full disk must not take the chatbot down,
so write errors are logged and swallowed. If you need the opposite — deny service
rather than lose an audit record — invert the `except` in `AuditLogger._write_file`
and be explicit about that choice in your risk register.

The audit table is append-only for the chatbot account (`INSERT` and nothing
else) and carries a trigger blocking `UPDATE`/`DELETE`, so a compromise of the
read-only account cannot erase its own tracks.

**Rejections are the signal to monitor.** A burst of `REJECTED` events from one
user is what an attempted bypass looks like from outside; `sql/03_audit_schema.sql`
includes the query.

## 6. Error handling design

Every failure is a stable code plus business-safe text plus `next_steps`.

| Code | Meaning | Typical next step |
|---|---|---|
| `SQL_VALIDATION_FAILED` | Guardrail rejection | Re-validate; use `rewritten_safe_sql` |
| `ACCESS_DENIED` | Role lacks clearance, or SQL not pre-approved | Validate first, or request a curated view |
| `OBJECT_NOT_ALLOWLISTED` | Object not approved | `list_allowed_tables` |
| `METADATA_UNAVAILABLE` | Object/schema metadata missing | Supply exact names |
| `QUERY_TIMEOUT` | Exceeded `call_timeout` | Narrow the filter, or aggregate |
| `DATABASE_UNAVAILABLE` | Network, listener or auth failure | Platform team |
| `QUERY_EXECUTION_FAILED` | Oracle rejected the statement | Re-check names |
| `UNKNOWN_DATABASE` | Not served by this process | Use `list_databases` |

Three principles:

**Oracle error text is never propagated.** `ORA-` messages routinely embed SQL
fragments and bind values; forwarding them would leak schema structure and data
through the model. Only the error *code* is surfaced; full text goes to the
server log alone.

**Denial messages do not confirm existence.** "Object not approved" and "you lack
clearance" read the same, because a distinguishable error is a schema oracle: an
attacker could enumerate real objects by watching which message comes back.
Covered by `test_denial_messages_do_not_disclose_object_existence`.

**Metadata degrades rather than fails.** If the database is unreachable,
`get_table_metadata` still returns policy-declared columns with
`metadata_source: "policy_only"`, so the chatbot can explain what exists even
during an outage.

## 7. Project structure

```
oracle-mcp-chatbot/
├── src/oracle_mcp/
│   ├── server.py       MCP entrypoint; FastMCP tool registration
│   ├── tools.py        the 8 tools; identity, approval cache, envelopes
│   ├── sql_guard.py    parse → inspect → rewrite  ← the core control
│   ├── policy.py       allowlist + RBAC
│   ├── masking.py      name-based and content-based masking
│   ├── metadata.py     ALL_* dictionary discovery, merged with policy
│   ├── reconcile.py    cross-database set comparison
│   ├── explain.py      deterministic result profiling
│   ├── audit.py        JSONL and Oracle audit sinks
│   ├── db.py           pools, read-only transactions, timeouts
│   ├── settings.py     env config; SecretStr credentials
│   └── errors.py       error taxonomy
├── config/policy/      onprem.yaml, atp.yaml, roles.yaml, masking.yaml
├── prompts/            system_prompt.md
├── sql/                read-only users, grants, audit schema
├── tests/              148 tests, no database required
├── mcp-clients/        Cursor / Claude Desktop configuration
├── docs/
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## 8. Alternatives considered

**Oracle SQLcl MCP Server / OCI Database Tools / ORDS MCP.** All are legitimate
and lower-effort. They were not chosen because none of them enforces the
column-level clearance model, output masking, or the validate-then-execute
fingerprint chain this brief calls for. A reasonable hybrid is to use SQLcl MCP
for developer-facing exploration in non-production, and this server for anything
business users touch.

**Regex-only SQL validation.** Rejected. Regex cannot reliably see statement
boundaries or nesting, and every deployment that has tried it has eventually lost
to comment or encoding tricks. AST parsing plus regeneration makes the class of
attack structurally impossible rather than enumerated.

**Masking in SQL rather than in Python.** Rejected as the primary mechanism.
SQL-side masking cannot inspect what a free-text column actually contains, so a
card number pasted into `NOTES` would pass straight through. The content scanners
need the values.
