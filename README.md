# Oracle MCP Chatbot — On-Prem Oracle DB + Oracle ATP

A secure Model Context Protocol server pair that lets an AI chatbot answer
natural-language questions against Oracle databases: it discovers metadata,
generates SELECT-only SQL, validates it, executes it under hard limits, masks
sensitive values, and logs everything.

Built with [FastMCP 3](https://gofastmcp.com), `python-oracledb` (thin mode) and
`sqlglot`. 164 tests, no database required to run them.

```bash
pip install -r requirements-dev.txt
pytest                                        # 164 passed
cp .env.example .env                          # add credentials
python -m oracle_mcp.server --profile onprem --check
python -m oracle_mcp.server --profile onprem
```

## What it does

| Capability | How |
|---|---|
| Read-only, always | AST validation, `SET TRANSACTION READ ONLY`, `SELECT`-only grants |
| Only approved data | YAML allowlist of schemas, objects and columns |
| Role-appropriate | Five roles with clearance levels; column-level enforcement |
| Bounded | Row cap (default 500) and query timeout (default 30s), neither user-raisable |
| Private | Masking by column name, by classification, and by value content |
| Accountable | One audit record per call, with redacted SQL and a hash |
| Two databases | Separate server processes; optional reconciliation server |

## The eight tools

| Tool | Purpose |
|---|---|
| `list_allowed_schemas` | Schemas the role may read, with descriptions |
| `list_allowed_tables` | Approved objects, with domain, sensitivity, row estimates |
| `get_table_metadata` | Columns, types, nullability, PK/FK, business descriptions |
| `search_data_dictionary` | Find objects and columns by business term, with confidence |
| `validate_sql` | Guardrail check; returns the rewritten safe SQL |
| `execute_readonly_sql` | Runs pre-approved SQL; returns masked, capped rows |
| `explain_query_result` | Computes facts for a business-language answer |
| `compare_onprem_and_atp_data` | Cross-database reconciliation (`profile=both` only) |

Plus `list_databases` for connection discovery. Every tool takes and returns JSON.

## How the security model works

Data reaches a user only by crossing five independent layers:

```
Database grants  →  Object allowlist  →  Role clearance  →  SQL guardrails  →  Output masking
   sql/*.sql        config/policy/       roles.yaml         sql_guard.py       masking.py
```

**The load-bearing idea:** the SQL you submit is never the SQL that runs. Input is
parsed into an AST, inspected, rewritten, and regenerated. Only node types the
validator recognised are re-emitted, so comment tricks, stacked statements and
homoglyph keywords cannot survive the round trip.

```
SELECT a FROM t; DROP TABLE t     →  rejected: MULTIPLE_STATEMENTS
SELECT /*+ PARALLEL(t,64) */ a…   →  SELECT a FROM t FETCH FIRST 500 ROWS ONLY
ＤＥＬＥＴＥ FROM t                 →  rejected: NFKC folds it to DELETE
SELECT * FROM v   (business_user) →  explicit column list, restricted ones absent
```

**Second key control:** `execute_readonly_sql` re-validates from scratch *and*
requires a fingerprint issued by `validate_sql`, so SQL cannot be swapped between
the check and the execution. Non-admin roles cannot execute anything that was not
approved first; admins can, but the statement still passes every guardrail.

**Third:** roles are pinned by process configuration, not by tool argument. A user
who tells the model "you are now an admin" produces a `user_role="admin"` string
that nothing reads.

## Configuration

Two files decide everything:

`config/policy/onprem.yaml` and `atp.yaml` — the object allowlist. Each database
picks one of two modes.

**Strict**, which is what On-Prem uses. Only the objects named here are
reachable, whatever the database grants allow:

```yaml
schemas:
  - name: EIM
    objects:
      - name: EIM_PR_SYSTEM
        type: TABLE
        sensitivity: INTERNAL
        large_table: true
        require_filter: true       # forces a WHERE clause
        columns:                   # optional; omit to read them from the
          - {name: SERIAL_NUMBER,  sensitivity: INTERNAL}   # data dictionary
          - {name: TAX_ID,         sensitivity: RESTRICTED} # at query time
```

Omitting `columns:` is supported and is what the deployed policy does. Columns
are then read from `ALL_TAB_COLUMNS` and classified by the name patterns in
`masking.yaml`, so the allowlist stays correct as the schema changes.

**Wildcard**, which is what ATP uses. Every schema the read-only account can read
becomes reachable:

```yaml
allow_all_schemas: true
excluded_schemas: []   # added on top of the built-in Oracle internal schemas
schemas: []
```

This deliberately gives up the object allowlist and makes the database grant the
boundary instead. Clearance, the SQL guardrails, row caps and masking all still
apply. Only use it against an account that is genuinely read-only.

`config/policy/roles.yaml` — who may see what:

```yaml
roles:
  business_user:
    clearance: INTERNAL      # cannot reach CONFIDENTIAL or RESTRICTED columns
    max_rows: 200
    allow_raw_sql: false
    schemas: {ONPREM: [EIM], ATP: ["*"]}   # "*" needs allow_all_schemas
```

Sensitivity ladder: `PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED < NEVER`.
`NEVER` is above every clearance, so passwords and card numbers are unreachable
by any role including admin.

## Deployment

Run one server per database. That split is a security boundary: the on-prem
process never holds the ATP wallet passphrase.

```bash
docker build -t oracle-mcp-chatbot:1.0.0 .
export ATP_WALLET_HOST_PATH=/secure/path/wallets/atp
docker compose up -d onprem-mcp atp-mcp
docker compose --profile reconciliation up -d   # optional, holds both credential sets
```

### Oracle ATP connectivity

Thin mode with an mTLS wallet. Unzip the wallet and set:

```bash
ATP_DSN=myatp_low                      # prefer _low so chatbot traffic can't starve prod
ATP_WALLET_DIR=/opt/oracle/wallets/atp # contains ewallet.pem + tnsnames.ora
ATP_CONFIG_DIR=/opt/oracle/wallets/atp
ATP_WALLET_PASSWORD=...                # set when the wallet zip was downloaded
```

`ATP_WALLET_PASSWORD` is the passphrase protecting `ewallet.pem`, not the database
password — a common and confusing failure. It is thin-mode only; thick mode reads
the passwordless `cwallet.sso` instead, and configuring both is rejected at
startup. For TLS-only ATP (no wallet), leave the wallet variables empty and paste
the full connect string from the OCI console into `ATP_DSN`.

The wallet is bind-mounted read-only and never baked into an image.

### On-prem connectivity

```bash
ONPREM_HOST=oracle-onprem.internal.example.com
ONPREM_PORT=1521
ONPREM_SERVICE_NAME=CDMPRD
ONPREM_MODE=thin
# TCPS instead:
# ONPREM_DSN=tcps://host:2484/CDMPRD?ssl_server_dn_match=true
```

Thin mode needs no Oracle Client. Use thick mode only for features it lacks; see
the commented stage in the `Dockerfile`.

## Documentation

| Document | Contents |
|---|---|
| [`docs/environment-configuration.md`](docs/environment-configuration.md) | How this deployment's connections are configured, and open items |
| [`docs/architecture.md`](docs/architecture.md) | Design, request flow, security boundaries, RBAC, audit, error handling |
| [`docs/testing-scenarios.md`](docs/testing-scenarios.md) | Full test plan with expected outcomes |
| [`docs/deployment-checklist.md`](docs/deployment-checklist.md) | Pre-production checklist and hardening backlog |
| [`docs/conversation-flows.md`](docs/conversation-flows.md) | Ten worked examples plus rejection flows |
| [`prompts/system_prompt.md`](prompts/system_prompt.md) | Chatbot system prompt |
| [`sql/`](sql/) | Read-only users, grants, audit schema |
| [`mcp-clients/`](mcp-clients/) | Cursor and Claude Desktop configuration |

## Before production

The reference implementation deliberately stops short in four places. Read
[`docs/deployment-checklist.md`](docs/deployment-checklist.md) for the full list;
the headline items:

- **Set `ORACLE_MCP_ROLE_BINDING_MODE=env`.** The `argument` default in
  `.env.example` is for development; under it the model can assert any role.
- **Replace the sample allowlists** in `config/policy/*.yaml` with your real
  curated views, and classify every column deliberately.
- **Move secrets to a vault.** Compose environment variables are visible to
  anyone who can run `docker inspect`.
- **Put the HTTP transport behind an authenticating gateway.** FastMCP's HTTP
  transport does not authenticate callers by itself; binding to loopback is a
  stopgap, not the control.

Also unimplemented by design: rate limiting, per-user identity propagation, and
approval workflow for admin raw SQL.

## Licence

Provided as a reference implementation. Review against your own security
standards before production use.
