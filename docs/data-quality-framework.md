# EIM data-quality framework

## Runtime flow

1. Connect to the `oracle-eim-dq` MCP server (`--profile both`).
2. Call `list_active_dq_rules`. The server reads only rows whose
   `RULE_STATUS = 'ACTIVE'` from `EIM.EIM_DQ_RULES_LOOKUP`.
3. Use `DQ_RULE` and `REFERENCE_CHECKPOINT` as context to prepare two aggregate
   queries for a selected rule:
   - one integer aliased `TOTAL_RECORDS`
   - one integer aliased `FAILED_RECORDS`
4. Call `execute_data_quality_rule`.
5. The server parses and independently validates both statements, restricts
   them to approved schemas, executes them in Oracle read-only transactions,
   calculates metrics, compares the previous local execution, and returns the
   required Markdown report.

Catalog text is never trusted as executable SQL. DML, DDL, PL/SQL, database
links, Oracle internal schemas, cartesian joins, and non-allowlisted objects are
rejected before execution.

## Metric contract

Example query shapes:

```sql
SELECT COUNT(*) AS TOTAL_RECORDS
FROM EIM.APPROVED_TABLE
```

```sql
SELECT COUNT(*) AS FAILED_RECORDS
FROM EIM.APPROVED_TABLE
WHERE REQUIRED_COLUMN IS NULL
```

Severity boundaries are deterministic:

- Critical: failure rate greater than 10%
- High: failure rate from 5% through 10%
- Medium: failure rate from 1% up to 5%
- Low: failure rate below 1%

At the shared 5% boundary, High takes precedence.

## Trend history

Results are appended to `logs/dq-history.jsonl`, which is ignored by Git.
Comparison uses the latest prior result for the same database and rule ID.
An increased failure percentage is explicitly reported as deterioration.

## Governance

- Adding a source object to `config/policy/*.yaml` is an approval decision.
- The database accounts should have only `CREATE SESSION` and `SELECT` grants.
- Keep credentials in `.env` or a secrets manager; never place them in MCP JSON.
- The ATP descriptor currently disables server-DN matching. Enable certificate
  hostname verification before production deployment.
- Rotate any password that has been shared in chat or another non-secret channel.

## Current catalog status

The live On-Prem catalog was reached through MCP on 2026-08-23. Its 20 columns,
including `REFERENCE_CHECKPOINT`, were discovered successfully, but the table
contained no rows and therefore no ACTIVE rules. The framework will return an
empty active-rule list until governed rows are populated.
