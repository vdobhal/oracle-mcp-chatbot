"""MCP server entrypoint.

Run one process per database:

    ORACLE_MCP_PROFILE=onprem python -m oracle_mcp.server
    ORACLE_MCP_PROFILE=atp    python -m oracle_mcp.server

and optionally a third for cross-database reconciliation:

    ORACLE_MCP_PROFILE=both   python -m oracle_mcp.server

Separate processes mean an On-Prem compromise cannot reach the ATP wallet: each
process only ever holds the credentials for the database it serves.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from fastmcp import FastMCP

from .audit import AuditLogger
from .db import ConnectionRegistry
from .policy import get_policy_store
from .settings import DB_NAME_BY_PROFILE, Settings, get_settings
from .tools import ToolService

logger = logging.getLogger("oracle_mcp")


def configure_logging(level: str) -> None:
    """Log to stderr only.

    Under the stdio transport, stdout carries the MCP protocol itself, so a
    single stray print would corrupt the session.
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )
    logging.getLogger("oracledb").setLevel(logging.WARNING)


def build_service(settings: Settings) -> ToolService:
    oracle_profiles = settings.oracle_profiles
    store = get_policy_store(
        settings.policy_dir,
        {
            profile.database_name: profile.policy_file
            for profile in oracle_profiles.values()
        },
    )
    registry = ConnectionRegistry(
        {name: profile for name, profile in oracle_profiles.items()},
        query_timeout_seconds=settings.query_timeout_seconds,
    )
    audit_connection = None
    if settings.audit_sink in {"db", "both"}:
        audit_db = DB_NAME_BY_PROFILE.get(settings.audit_db_profile, "")
        if audit_db in registry.names:
            audit_connection = registry.get(audit_db)
        else:
            logger.warning(
                "Audit sink %r requested but profile %s is not served here; "
                "falling back to file only.",
                settings.audit_sink,
                settings.audit_db_profile,
            )
    audit = AuditLogger(
        sink=settings.audit_sink if audit_connection or settings.audit_sink != "db" else "file",
        file_path=settings.audit_file,
        table_name=settings.audit_table,
        connection=audit_connection,
    )
    return ToolService(settings=settings, store=store, registry=registry, audit=audit)


def create_server(settings: Settings | None = None) -> FastMCP:
    settings = settings or get_settings()
    service = build_service(settings)
    scope = ", ".join(service.registry.names)
    mcp = FastMCP(
        name=f"oracle-mcp-{settings.profile}",
        instructions=(
            f"Read-only Oracle access for {scope}. Discover metadata with "
            "list_allowed_schemas, list_allowed_tables, get_table_metadata and "
            "search_data_dictionary before writing SQL. Every statement must pass "
            "validate_sql, and execute_readonly_sql must be given exactly the "
            "rewritten_safe_sql that validate_sql returned. Never invent object or "
            "column names. For EIM data quality, call list_active_dq_rules first and "
            "execute only ACTIVE rules through execute_data_quality_rule."
        ),
    )

    @mcp.tool
    def list_databases() -> dict[str, Any]:
        """List the Oracle databases this server can query, with guardrail limits.

        Returns connection metadata only. Credentials, hostnames, wallets and
        connection strings are never included.
        """
        return service.list_databases()

    @mcp.tool
    def list_allowed_schemas(database_name: str, user_role: str = "") -> dict[str, Any]:
        """List the schemas this chatbot is authorised to read on a database.

        Args:
            database_name: ONPREM or ATP.
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.list_allowed_schemas(database_name, user_role or None)

    @mcp.tool
    def list_allowed_tables(
        database_name: str, schema_name: str, user_role: str = ""
    ) -> dict[str, Any]:
        """List approved tables and views in a schema.

        Includes business description, business domain, data sensitivity and an
        estimated row count where statistics are available.

        Args:
            database_name: ONPREM or ATP.
            schema_name: Schema to list, from list_allowed_schemas.
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.list_allowed_tables(database_name, schema_name, user_role or None)

    @mcp.tool
    def get_table_metadata(
        database_name: str, schema_name: str, table_name: str, user_role: str = ""
    ) -> dict[str, Any]:
        """Describe an approved table or view.

        Returns columns, data types, nullability, primary key, foreign keys and
        business descriptions. Columns above the caller's clearance are omitted.

        Args:
            database_name: ONPREM or ATP.
            schema_name: Owning schema.
            table_name: Table or view name.
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.get_table_metadata(
            database_name, schema_name, table_name, user_role or None
        )

    @mcp.tool
    def search_data_dictionary(
        database_name: str, search_text: str, user_role: str = ""
    ) -> dict[str, Any]:
        """Search approved metadata for tables and columns matching a business term.

        Use this before writing SQL to find the right object. Returns matches with
        a confidence score based on term overlap with approved metadata.

        Args:
            database_name: ONPREM or ATP.
            search_text: Business term, for example "EA contract id" or "tax registration".
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.search_data_dictionary(database_name, search_text, user_role or None)

    @mcp.tool
    def validate_sql(
        database_name: str, sql_text: str, user_role: str = ""
    ) -> dict[str, Any]:
        """Validate SQL against the read-only guardrails before execution.

        Enforces SELECT-only, single-statement, allowlisted objects and columns,
        no cartesian joins, mandatory filters on large objects, and a row cap.
        Returns rewritten_safe_sql, which is the only text execute_readonly_sql
        will accept.

        Args:
            database_name: ONPREM or ATP.
            sql_text: The candidate SELECT statement.
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.validate_sql(database_name, sql_text, user_role or None)

    @mcp.tool
    def execute_readonly_sql(
        database_name: str,
        validated_sql: str,
        user_id: str = "",
        request_id: str = "",
        bind_parameters: dict[str, Any] | None = None,
        user_role: str = "",
    ) -> dict[str, Any]:
        """Execute a validated read-only SELECT and return masked rows.

        Re-validates the SQL independently, then requires that this exact
        statement was approved by validate_sql. Sensitive values are masked and
        the result is capped and timed out.

        Args:
            database_name: ONPREM or ATP.
            validated_sql: Exactly the rewritten_safe_sql returned by validate_sql.
            user_id: Caller identity for the audit trail.
            request_id: Correlation id; generated when omitted.
            bind_parameters: Values for any bind variables in the statement.
            user_role: Requesting role. Ignored when the server pins roles by configuration.
        """
        return service.execute_readonly_sql(
            database_name,
            validated_sql,
            user_id or None,
            request_id or None,
            bind_parameters,
            user_role or None,
        )

    @mcp.tool
    def list_active_dq_rules(user_role: str = "") -> dict[str, Any]:
        """List governed EIM data-quality rules whose RULE_STATUS is ACTIVE.

        Returns DQ_RULE and REFERENCE_CHECKPOINT as business context. Neither
        field is executed as SQL; all executable statements must independently
        pass the read-only SQL guard.
        """
        return service.list_active_dq_rules(user_role or None)

    @mcp.tool
    def execute_data_quality_rule(
        rule_id: str,
        target_database: str,
        total_records_sql: str,
        failed_records_sql: str,
        user_role: str = "",
        user_id: str = "",
    ) -> dict[str, Any]:
        """Evaluate one ACTIVE EIM DQ rule and return metrics plus a Markdown report.

        Both SQL inputs must be aggregate SELECT statements over approved objects.
        ``total_records_sql`` must return one integer aliased TOTAL_RECORDS;
        ``failed_records_sql`` must return one integer aliased FAILED_RECORDS.
        INSERT, UPDATE, DELETE, MERGE, TRUNCATE, DDL, PL/SQL, database links and
        unapproved objects are rejected before Oracle sees the statement.

        The result includes total and failed records, pass/failure percentages,
        severity, previous-run trend, corrective actions, and all required report
        sections.
        """
        return service.execute_data_quality_rule(
            rule_id,
            target_database,
            total_records_sql,
            failed_records_sql,
            user_role or None,
            user_id or None,
        )

    @mcp.tool
    def explain_query_result(
        user_question: str,
        sql_text: str = "",
        query_result: dict[str, Any] | None = None,
        table_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Profile a result set into facts for a business-language answer.

        Computes row counts, null rates, distinct counts, ranges, common values
        and data quality flags. Use these figures verbatim; do not estimate.

        Args:
            user_question: The original business question.
            sql_text: The SQL that produced the result.
            query_result: The full envelope returned by execute_readonly_sql.
            table_metadata: Optional output of get_table_metadata for context.
        """
        return service.explain_query_result(
            user_question, sql_text, query_result, table_metadata
        )

    if settings.reconciliation_enabled:

        @mcp.tool
        def compare_onprem_and_atp_data(
            business_entity: str,
            matching_key: str,
            onprem_query: str,
            atp_query: str,
            user_role: str = "",
            compare_columns: list[str] | None = None,
            user_id: str = "",
        ) -> dict[str, Any]:
            """Reconcile a business entity between On-Prem Oracle DB and Oracle ATP.

            Both queries are validated before either runs. Returns matched and
            unmatched counts, source-only and target-only keys, attribute-level
            mismatches and a recommendation.

            Args:
                business_entity: What is being reconciled, for example "Customer master".
                matching_key: Business key column(s), comma separated, present in both results.
                onprem_query: SELECT against approved On-Prem objects.
                atp_query: SELECT against approved ATP objects.
                user_role: Requesting role. Ignored when the server pins roles by configuration.
                compare_columns: Attributes to compare; defaults to all shared non-key columns.
                user_id: Caller identity for the audit trail.
            """
            return service.compare_onprem_and_atp_data(
                business_entity,
                matching_key,
                onprem_query,
                atp_query,
                user_role or None,
                compare_columns,
                user_id or None,
            )

    logger.info(
        "MCP server ready: profile=%s databases=%s transport=%s role_binding=%s max_rows=%d",
        settings.profile,
        scope,
        settings.transport,
        settings.role_binding_mode,
        settings.max_rows,
    )
    if settings.role_binding_mode == "argument":
        logger.warning(
            "role_binding_mode=argument: the caller can assert any role. "
            "Use 'env' outside development."
        )
    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Secure Oracle MCP server")
    parser.add_argument("--profile", choices=["onprem", "atp", "both"])
    parser.add_argument("--transport", choices=["stdio", "http"])
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate configuration and connectivity, then exit.",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    if args.profile:
        settings = settings.model_copy(update={"profile": args.profile})
    if args.transport:
        settings = settings.model_copy(update={"transport": args.transport})
    if args.host:
        settings = settings.model_copy(update={"http_host": args.host})
    if args.port:
        settings = settings.model_copy(update={"http_port": args.port})

    configure_logging(settings.log_level)

    if args.check:
        return _healthcheck(settings)

    mcp = create_server(settings)
    if settings.transport == "http":
        mcp.run(transport="http", host=settings.http_host, port=settings.http_port)
    else:
        mcp.run(transport="stdio")
    return 0


def _healthcheck(settings: Settings) -> int:
    service = build_service(settings)
    failures = 0
    for name in service.registry.names:
        connection = service.registry.get(name)
        ok = connection.ping()
        print(f"{name}: {'OK' if ok else 'FAILED'}")
        failures += 0 if ok else 1
    for database_name, policy in service.store.databases.items():
        objects = sum(len(s.objects) for s in policy.schemas)
        if policy.discovery_enabled:
            # Counting only declared objects reports "0 schema(s), 0 approved
            # object(s)" for a database in discovery mode, which reads as broken
            # when it is in fact working and wide open.
            scope = (
                ", ".join(sorted(policy.discovered_schemas))
                if policy.discovered_schemas
                else "every readable schema"
            )
            print(f"{database_name}: discovery mode over {scope}")
            if policy.excluded_objects:
                print(f"{database_name}: {len(policy.excluded_objects)} object exclusion(s)")
            if policy.domains:
                names = ", ".join(d.name for d in policy.domains)
                print(f"{database_name}: domains {names}")
            if objects:
                print(f"{database_name}: {objects} additionally declared object(s)")
        else:
            print(
                f"{database_name}: {len(policy.schemas)} schema(s), "
                f"{objects} approved object(s)"
            )
    print(f"roles: {', '.join(sorted(service.store.roles))}")
    service.registry.close_all()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
