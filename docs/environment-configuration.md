# Environment configuration notes

Records how the supplied connection details map onto this server's settings, and
the issues that need a decision before this reaches business users.

Real values live in `.env`, which is gitignored. This file deliberately contains
no passwords.

## Connection mapping

### On-Prem

| Supplied | Setting | Value |
|---|---|---|
| Host | `ONPREM_HOST` | `10.103.160.118` |
| Port | `ONPREM_PORT` | `1521` |
| Service | `ONPREM_SERVICE_NAME` | `s2eim.corp.netapp.com` |
| User | `ONPREM_USER` | `EIM_APPSRO` |
| Password | `ONPREM_PASSWORD` | in `.env` |

Resolves to the EZConnect DSN
`10.103.160.118:1521/s2eim.corp.netapp.com`.

The host is a direct listener address. Thin mode connects to that host, port,
and service with no extra client-side load balancing.

### ATP

The supplied JDBC URL converts to a `python-oracledb` DSN by removing the
`jdbc:oracle:thin:@` prefix and keeping the descriptor from `(description=`
onward. Thin mode accepts a full TNS descriptor as the DSN.

| Property | Value |
|---|---|
| Protocol | `tcps` (TLS) |
| Host / port | `erpatp3stg.oci.netapp.com` : `1522` |
| Service | `gb3612eca320d0d_s3erpatp_tp.adb.oraclecloud.com` |
| User | `NAPP_READONLY` |
| Wallet | none — TLS only, not mTLS |

Because this is TLS-only, `ATP_WALLET_DIR`, `ATP_CONFIG_DIR` and
`ATP_WALLET_PASSWORD` are all empty. Setting a wallet directory here would make
the driver search for an `ewallet.pem` that does not exist, producing a
confusing PEM passphrase error rather than a clear one.

## Verify the configuration

```bash
cd oracle-mcp-chatbot
python -m oracle_mcp.server --profile both --check
```

Expected on success:

```
ONPREM: OK
ATP: OK
```

`FAILED` means the network path, credentials or TLS settings need attention; the
server log line above it carries the Oracle error code.

## Query cache and performance observability

The process has a bounded in-memory TTL cache for validated read results.
Cache keys include database, effective role, rewritten SQL, bind values, and
row limit. This prevents results from crossing database or masking boundaries.
Only already-masked payloads are cached. The cache is process-local and is
cleared on restart.

| Setting | Default | Purpose |
|---|---:|---|
| `ORACLE_MCP_QUERY_CACHE_ENABLED` | `true` | Enables query and summary caches |
| `ORACLE_MCP_QUERY_CACHE_TTL_SECONDS` | `60` | TTL for ordinary query results |
| `ORACLE_MCP_QUERY_CACHE_MAX_ENTRIES` | `256` | LRU entry ceiling |
| `ORACLE_MCP_QUERY_CACHE_MAX_ROWS` | `1000` | Excludes large result sets from the generic cache |
| `ORACLE_MCP_SUMMARY_CACHE_TTL_SECONDS` | `300` | TTL for compact expensive summaries |
| `ORACLE_MCP_SLOW_QUERY_THRESHOLD_MS` | `5000` | Emits slow-query and slow-HTTP warnings |

`GET /api/metrics` reports cache hits, misses, hit rate, database calls,
average/max database time, errors, slow queries, and per-database totals. It
does not expose SQL, bind values, credentials, or result rows. `/api/health`
also includes the same performance snapshot. Every HTTP response includes a
`Server-Timing` header with application duration. Chat tool traces include
`duration_ms` and `cache_hit`, which makes slow steps visible in the UI.

Cache entries do not bypass validation, authorization, or masking. A statement
must pass the normal guardrails before its cache key is considered.

---

## Open items

### 1. Verify the `EIM_APPSRO` database grants

The supplied account is named as a read-only account, but its grants still need
to be verified. It should have only `CREATE SESSION` and `SELECT` on the
allowlisted objects. Confirm the boundary directly:

```sql
-- as the chatbot account; must fail with ORA-01031
INSERT INTO <some_allowlisted_table> (id) VALUES (1);
```

`NAPP_READONLY` on ATP looks correct by name. Worth confirming the grants match:

```sql
SELECT privilege FROM user_sys_privs;
SELECT granted_role FROM user_role_privs;   -- DWROLE should NOT appear
```

### 2a. RESOLVED — ATP failed TLS because Python had no CA bundle

Worth recording because the error message pointed the wrong way. The connection
failed with:

```
DPY-6005: cannot connect to database
[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain
```

That reads like an interception proxy or a bad server certificate. It was
neither. `openssl s_client` verified the chain cleanly — a genuine Oracle
certificate signed by DigiCert Global Root G2. The problem was local:

```
openssl cafile : .../Python.framework/Versions/3.13/etc/openssl/cert.pem  exists: False
default ctx CA count: 0
```

The macOS python.org build ships no CA bundle until `Install
Certificates.command` is run. With an empty trust store OpenSSL cannot anchor
any chain, so it describes the unanchored root as "self-signed". Any TLS from
this interpreter would have failed the same way.

Fixed by pointing OpenSSL at certifi's bundle via `SSL_CERT_FILE` in `.env`.
The system-wide alternative is running the installer once:

```bash
"/Applications/Python 3.13/Install Certificates.command"
```

Diagnostic worth keeping, since the symptom is easy to misread:

```bash
python3 -c "import ssl; print(len(ssl.create_default_context().get_ca_certs()))"
```

`0` means the trust store is empty and the fault is local, not the server.

### 2b. `ssl_server_dn_match=no` disables certificate verification

The ATP descriptor sets `(security=(ssl_server_dn_match=no))`. This tells the
driver not to check that the certificate presented actually belongs to the host
it dialled. TLS still encrypts the traffic, but it no longer proves *who* is on
the other end, which is the property that defends against an interposed server.

`no` is often set to work around a certificate or hostname mismatch during
setup. If it was carried over from such a workaround, change it to `yes` in
`ATP_DSN` and confirm the connection still succeeds. ATP presents certificates
that match the endpoint, so this normally works without further changes.

### 3. Consider the `_low` service for chatbot traffic

The service is `..._s3erpatp_tp...` — the transaction-processing service. ATP
also publishes `_low`, `_medium` and `_high`. `_low` gives the smallest CPU share
and no parallelism, which keeps ad-hoc chatbot queries from competing with
application workload. Switching means changing `_tp` to `_low` in the
`service_name` inside `ATP_DSN`.

### 4. Rotate the credentials that were shared in chat

Both passwords were sent through a chat interface, so they should be treated as
disclosed and rotated. Afterwards, source them from OCI Vault or an approved
secret manager rather than a file on disk. Real environment variables override
`.env`, so vault injection needs no code change.

### 5. The two databases now use different access models

This is worth understanding because the security properties are not the same.

**On-Prem is strictly allowlisted.** `config/policy/onprem.yaml` names the
lookup-catalog objects, the routing catalog, and the EIM Install Base skill
tables and views. Nothing else is reachable, whatever the grants say:

| Object | Filter required |
|---|---|
| `EIM.EIM_PR_SYSTEM` | yes |
| `EIM.EIM_DRM_PRODUCT_DETAILS` | no |
| `EIM.EIM_PR_SN_SO_REF` | yes |
| `EIM.EIM_PR_IB_LATEST` | yes |
| `EIM.EIM_PR_ROLES` | no |
| `EIM.EIM_CONFIG_DETAILS` | yes |
| `EIM.EIM_PR_HEADSWAP` | yes |
| `EIM.EIM_IB_CONFIG_LATEST_PUB` | yes |
| `EIM.EIM_PR_SN_SO_REF_PUB` | yes |
| `EIM.EIM_CONTRACT_LINES_PUB_VW` | yes |
| `EIM.EIM_IB_LATEST_PUB` | yes |
| `EIM.EIM_CONFIG_DETAIL_VW` | yes |
| `EIM.EIM_OPPTY_DETAILS` | yes |
| `EIM.EIM_OPPTY_SN_DETAILS` | yes |
| `EIM.EIM_OPPTY_DETAILS_VW` | yes |
| `EIM.EIM_PROTOCOL_DETAILS_VW` | yes |
| `EIM.EIM_PRODUCT_DETAIL_VW` | no |
| `EIM_APPS.EIM_AI_LOOKUP_DETAILS` | no |

**ATP is scoped discovery.** `discovered_schemas` is `NAPPERP`, `NAPPERPADM`,
and `NAPPERPDS`. The routing catalog's CDM tables
`NAPPERP.NAPP_CDM_TO_ATP_SYNC` and `NAPPERP.NAPP_GTM_CDM_INBOUND_MSGS` are in
that scope (and declared with descriptions). Dump/backup/temp names are
excluded. This is narrower than `allow_all_schemas: true`.

The other four layers are unchanged on both databases — role clearance, the SQL
guardrails, row caps and timeouts, and output masking. What ATP loses is the
independent check that an object was *reviewed and approved* for chatbot use, as
opposed to merely being readable.

That makes the `NAPP_READONLY` grant the thing to verify, since it is now doing
the work the allowlist used to do:

```sql
SELECT * FROM user_sys_privs;    -- expect CREATE SESSION and little else
SELECT * FROM user_role_privs;   -- DWROLE should NOT appear
```

To tighten ATP later, set `allow_all_schemas: false` and list schemas and
objects the way `onprem.yaml` does.

#### Columns are discovered, not declared

Neither policy file lists columns. Columns are read from `ALL_TAB_COLUMNS` at
query time and classified by the naming rules in `config/policy/masking.yaml`,
so a column called `TAX_ID` is treated as `RESTRICTED` and one called
`CONTACT_EMAIL` as `CONFIDENTIAL` without anyone hand-listing them. Queries
against columns above the caller's clearance are refused at validation, and
anything that slips through is masked on the way out.

The trade-off: a sensitive column whose name matches no rule is classified
`INTERNAL` and will be readable by every role. Inference is a reasonable default,
not a substitute for classification. Once you know these On-Prem objects, worth
reviewing their columns and either extending `masking.yaml` or pinning a
`columns:` block on the object, which switches it to declared mode:

```sql
SELECT column_name, data_type, nullable
  FROM all_tab_columns
 WHERE owner = :owner AND table_name = :table_name
 ORDER BY column_id;
```

Also note `require_filter: true` on the large EIM tables, which forces a `WHERE`
clause so a question cannot turn into a full table scan. If any of these objects is
actually small, dropping the flag makes it easier to query.
