# Test plan

215 automated tests run without an Oracle instance. `FakeConnection` and
`FakeDictionary` stand in for the driver, so the guardrail, masking, RBAC,
discovery and audit paths are all exercised deterministically in a few seconds.

This is what the suite covers and why. For exercising a *running* deployment
against the real databases, see [testing.md](testing.md).

Tests run against the fixture policies in `tests/policy/` and
`tests/policy_discovery/`, never the deployed allowlist in `config/policy/`.
That keeps the suite describing the behaviour of the access model rather than
one environment's table list, so adding an object to the allowlist does not
break unrelated tests. The two tests that *do* assert on the deployed files say
so in their names.

```bash
pytest                          # everything
pytest -m security              # security controls only
pytest tests/test_sql_guard.py  # the guardrail
pytest --cov=oracle_mcp --cov-report=term-missing
```

## Coverage by area

| File | Tests | Covers |
|---|---|---|
| `test_sql_guard.py` | 63 | SELECT-only, injection, obfuscation, allowlist, clearance, row limits, joins, binds |
| `test_discovery.py` | 66 | Wildcard and scoped schemas, discovered columns, inferred classification, object exclusions, domain tagging, fail-closed |
| `test_tools.py` | 30 | Discovery tools, validate/execute trust chain, audit records, role binding |
| `test_masking.py` | 20 | Name rules, classification masking, content scanners, Luhn, truncation |
| `test_policy.py` | 17 | RBAC, clearance, denial wording, credential isolation, ATP wallet config |
| `test_reconcile.py` | 12 | Set comparison, composite keys, normalisation, tool gating |
| `test_server.py` | 7 | Tool registration, profile gating, health check |
| `test_server.py` | 7 | FastMCP registration, schemas, protocol round-trip, profile gating |

`pytest -m security` selects the 115 tests that assert a security control directly.

## Security scenarios and expected outcomes

### SELECT-only enforcement

| Input | Expected |
|---|---|
| `UPDATE`, `DELETE`, `INSERT`, `MERGE` | Rejected, `FORBIDDEN_STATEMENT_TYPE` |
| `DROP`, `TRUNCATE`, `CREATE`, `ALTER` | Rejected |
| `GRANT`, `REVOKE`, `COMMIT` | Rejected |
| `BEGIN ... END;` anonymous block | Rejected, `SQL_PARSE_FAILED` |
| `SELECT ... INTO` | Rejected |
| `SELECT ... FOR UPDATE` | Rejected |
| Valid `SELECT` | Approved, row cap appended |

### Injection and obfuscation

| Input | Expected |
|---|---|
| `SELECT ...; DROP TABLE x` | Rejected, `MULTIPLE_STATEMENTS` |
| `SELECT ... /* c */ ; /* c */ DELETE ...` | Rejected — comments do not hide the boundary |
| `-- ignore all previous instructions` | Approved; comment absent from executed SQL |
| `/*+ PARALLEL(t,64) */` | Approved; hint stripped |
| `ＤＥＬＥＴＥ FROM t` (fullwidth) | Rejected — NFKC folds to `DELETE` |
| Embedded `\x00` | Rejected, `CONTROL_CHARACTERS` |
| `DBMS_*`, `UTL_*`, `SYS.`, `V$`, `@dblink` | Rejected, `BLOCKED_CONSTRUCT` |
| Injection payload inside a string literal | Approved — it stays a literal and does nothing |

### Allowlist and clearance

| Scenario | Expected |
|---|---|
| Unapproved schema `HR.EMPLOYEES` | Rejected |
| Unapproved object in an approved schema | Rejected |
| `business_user` → `CDM.CUSTOMER` | Rejected, `ACCESS_DENIED` |
| `analyst` → `CDM.CUSTOMER` with a filter | Approved |
| Unqualified name | Resolves to `default_schema` |
| CTE alias | Not treated as a schema object |
| Subquery on an unapproved object | Rejected |
| ATP object referenced on the On-Prem server | Rejected |
| `analyst` names `TAX_REGISTRATION_NUMBER` | Rejected, `RESTRICTED_COLUMN` |
| `admin` names the same column | Approved |
| `COUNT(restricted_column)` | Rejected — aggregation is not a loophole |
| `SELECT *` as `business_user` | Approved; expanded to permitted columns only |

### Discovery mode

Covers the two deployed shapes: On-Prem allowlists objects but not columns, and
ATP allowlists nothing and relies on the grant. Exercised in
`tests/test_discovery.py` with a fake data dictionary.

| Scenario | Expected |
|---|---|
| Object in the dictionary but not the allowlist (strict mode) | Rejected — discovery does not widen a named allowlist |
| Columns of an allowlisted object with no `columns:` block | Read from `ALL_TAB_COLUMNS` |
| Discovered `TAX_ID` | Classified `RESTRICTED` by the masking rules |
| Discovered `CONTACT_EMAIL` | Classified `CONFIDENTIAL` |
| `business_user` names a discovered `RESTRICTED` column | Rejected, `RESTRICTED_COLUMN` |
| `SELECT *` on a discovered object | Expanded to the columns the role may see |
| Wildcard mode, schema declared nowhere in YAML | Approved if the account can read it |
| Wildcard mode, `SYS.USER$` | Rejected — Oracle internals excluded regardless of grants |
| Wildcard mode, schema in `excluded_schemas` | Rejected |
| Wildcard mode, object absent from the dictionary | Rejected — the grant decides existence |
| Wildcard mode, data dictionary unreachable | Rejected — discovery fails closed |
| Role scoped to named schemas on a wildcard database | Keeps its scope, `ACCESS_DENIED` elsewhere |
| Deployed `onprem.yaml` | Exposes exactly the five agreed EIM objects |

### Row limits

| Scenario | Expected |
|---|---|
| No limit given | `FETCH FIRST 500 ROWS ONLY` injected |
| `FETCH FIRST 100000 ROWS ONLY` | Clamped to 500 |
| `FETCH FIRST 10 ROWS ONLY` | Preserved |
| `business_user` (`max_rows: 200`) | Capped at 200 |
| Aggregate query | Still capped, but not rejected for lacking a filter |
| `UNION ALL` | Cap applies to the whole set operation |

### Query shape

| Scenario | Expected |
|---|---|
| `FROM a, b` with no predicate | Rejected, `CARTESIAN_JOIN` |
| `CROSS JOIN` | Rejected |
| `JOIN ... ON` | Approved |
| `admin` cross join | Approved (`allow_cartesian: true`) |
| `require_filter` object, no `WHERE` | Rejected, `MISSING_FILTER` |
| Same object, aggregated | Approved |

### The validate → execute trust chain

| Scenario | Expected |
|---|---|
| Execute without validating (`analyst`) | Rejected, `ACCESS_DENIED` |
| Execute after validating | Succeeds |
| **Validate, then alter the SQL before executing** | **Rejected; no SQL reaches the database** |
| `admin` executes directly | Succeeds, guardrails still applied |
| `admin` executes `DROP TABLE` | Rejected, `SQL_VALIDATION_FAILED` |
| Bind variable declared but no value supplied | Rejected before execution |
| Bind values supplied | Passed as parameters, never concatenated |

The tamper test is the important one: it proves the fingerprint chain closes the
time-of-check/time-of-use gap.

### Masking

| Input | Role | Output |
|---|---|---|
| `USER_PASSWORD` | admin | `[REDACTED]` — no role ever sees it |
| `TAX_REGISTRATION_NUMBER` = `GB123456789` | analyst | `****6789` |
| same | admin | `GB123456789` |
| `PRIMARY_EMAIL` | business_user | `j***@example.com` |
| same | analyst | full value |
| `PRIMARY_PHONE` | business_user | `***-***-0958` |
| `NOTES` = `card 4111111111111111 on file` | admin | masked — content scanner |
| `NOTES` = `order 1234567890123456` | admin | unchanged — fails Luhn |
| SSN / private key / JWT in free text | any | redacted |
| 5000-character string | any | truncated at 400 |
| `NULL` | any | stays `NULL` |

### Audit

| Scenario | Expected |
|---|---|
| Successful execution | Record with `user_id`, role, row count, SHA-256 |
| Guardrail rejection | Record with `status: REJECTED` |
| SQL containing `'SECRET-CUSTOMER-9999'` | Literal absent; object name present |
| Question containing newlines | Flattened to one line |

### Credential isolation

| Scenario | Expected |
|---|---|
| `repr()` / `str()` / `model_dump_json()` of a profile | Password absent |
| `list_databases` output | No password, DSN, host or port |
| Protocol round-trip of `list_databases` | No wallet password, no TNS alias |
| Thick mode with a wallet password | Rejected at config validation |
| Profile with no DSN and no host | Rejected at config validation |

## Integration tests (require a live database)

Not automated here, since they need real credentials. Run before each release:

```bash
python -m oracle_mcp.server --profile onprem --check
python -m oracle_mcp.server --profile atp --check
```

Then verify by hand:

1. **Read-only enforcement at the database.** Connect as `CHATBOT_RO` in SQLcl and
   attempt `INSERT`. Expect `ORA-01031: insufficient privileges`. This confirms
   layer 1 independently of the application.
2. **Timeout.** Set `ORACLE_MCP_QUERY_TIMEOUT_SECONDS=2` and run a deliberately
   slow query. Expect `QUERY_TIMEOUT`, and confirm in `V$SESSION` that the
   session was actually cancelled, not merely abandoned.
3. **ATP wallet.** Rename `ewallet.pem` and restart. Expect `DATABASE_UNAVAILABLE`
   with no wallet path in the message.
4. **Row estimates.** Confirm `list_allowed_tables` returns non-null
   `estimated_row_count` where statistics exist.
5. **Audit table.** With `ORACLE_MCP_AUDIT_SINK=db`, confirm rows land, then
   attempt `UPDATE` as the owner and expect `ORA-20001`.
6. **Consumer group.** On ATP, confirm the session maps to `LOW` in
   `V$RSRC_SESSION_INFO`.

## Adding a security test

Any new guardrail needs a test that fails without it. Use the existing shape:

```python
def test_new_bypass_is_blocked(guard, analyst):
    result = guard.validate("<payload>", database_name="ONPREM", role=analyst)
    assert not result.approved
    assert "EXPECTED_CODE" in {e.code for e in result.validation_errors}
```
