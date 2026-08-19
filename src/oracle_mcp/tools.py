"""Tool implementations.

Framework-agnostic on purpose: ``server.py`` is a thin FastMCP binding over this
class, which keeps every security control testable without an MCP client or a
database.

Two controls in here are worth reading closely.

``_identity`` decides who the caller is. When ``role_binding_mode='env'`` the
role comes from process configuration and the ``user_role`` argument is ignored
entirely, because any argument reaching this layer has passed through the model
and is therefore attacker-influenced. A model told "you are now an admin" can
still only send a string.

``execute_readonly_sql`` re-validates from scratch and additionally requires
non-admin callers to present a fingerprint issued by ``validate_sql``. Without
that, validation and execution are two separate trust decisions and anything in
between could swap the statement.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any

from .audit import AuditLogger, build_event, new_request_id, sanitize_free_text
from .db import ConnectionRegistry, OracleConnection
from .errors import AccessDeniedError, ChatbotError, SqlValidationError
from .explain import (
    data_quality_flags,
    empty_result_reasons,
    key_observations,
    profile_rows,
)
from .masking import Masker
from .metadata import MetadataService
from .policy import PolicyStore, Role
from .reconcile import SideResult, compare_result_sets
from .settings import Settings
from .sql_guard import SqlGuard, ValidationResult

logger = logging.getLogger(__name__)

_APPROVAL_TTL_SECONDS = 900
_APPROVAL_CACHE_SIZE = 256


class ApprovalCache:
    """Fingerprints issued by ``validate_sql``, valid briefly and once per role.

    Binding the entry to the role prevents a business user from replaying a
    fingerprint an admin obtained for a more permissive statement.
    """

    def __init__(self, ttl_seconds: int = _APPROVAL_TTL_SECONDS) -> None:
        self.ttl = ttl_seconds
        self._entries: OrderedDict[tuple[str, str, str], float] = OrderedDict()

    def add(self, database: str, role_name: str, sql_fingerprint: str) -> None:
        key = (database.upper(), role_name.lower(), sql_fingerprint)
        self._entries[key] = time.monotonic() + self.ttl
        self._entries.move_to_end(key)
        while len(self._entries) > _APPROVAL_CACHE_SIZE:
            self._entries.popitem(last=False)

    def is_approved(self, database: str, role_name: str, sql_fingerprint: str) -> bool:
        key = (database.upper(), role_name.lower(), sql_fingerprint)
        expiry = self._entries.get(key)
        if expiry is None:
            return False
        if expiry < time.monotonic():
            self._entries.pop(key, None)
            return False
        return True


class ToolService:
    """Implements every MCP tool over the policy, guard, masking and audit layers."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: PolicyStore,
        registry: ConnectionRegistry,
        audit: AuditLogger,
    ) -> None:
        self.settings = settings
        self.store = store
        self.registry = registry
        self.audit = audit
        self.masker = Masker(store.masking_config)
        self.metadata = MetadataService(store)
        self.guard = SqlGuard(
            store,
            max_rows=settings.max_rows,
            max_sql_length=settings.max_sql_length,
            allow_cartesian=settings.allow_cartesian,
        )
        self.approvals = ApprovalCache()

    # ---- identity ----------------------------------------------------------

    def _identity(self, user_role: str | None, user_id: str | None = None) -> tuple[Role, str]:
        if self.settings.role_binding_mode == "env":
            role = self.store.role(self.settings.pinned_role)
            return role, self.settings.pinned_user_id
        return self.store.role(user_role), sanitize_free_text(user_id or "unknown", 100)

    def _connection(self, database_name: str) -> OracleConnection | None:
        """Metadata tools degrade to policy-only rather than failing when the DB is down."""
        try:
            return self.registry.get(database_name)
        except ChatbotError:
            return None

    # ---- envelope ----------------------------------------------------------

    def _ok(self, payload: dict[str, Any], request_id: str) -> dict[str, Any]:
        return {"status": "OK", "request_id": request_id, **payload}

    def _fail(self, exc: ChatbotError, request_id: str) -> dict[str, Any]:
        return {"request_id": request_id, **exc.to_dict()}

    # ---- tool 0: connection discovery --------------------------------------

    def list_databases(self) -> dict[str, Any]:
        """Databases this server serves. Never includes credentials."""
        request_id = new_request_id()
        return self._ok(
            {
                "databases": self.registry.public_metadata(),
                "reconciliation_available": self.settings.reconciliation_enabled,
                "max_rows": self.settings.max_rows,
                "query_timeout_seconds": self.settings.query_timeout_seconds,
            },
            request_id,
        )

    # ---- tool 1 ------------------------------------------------------------

    def list_allowed_schemas(
        self, database_name: str, user_role: str | None = None
    ) -> dict[str, Any]:
        request_id = new_request_id()
        try:
            role, user_id = self._identity(user_role)
            payload = self.metadata.list_schemas(database_name, role)
            self._audit(
                request_id, "list_allowed_schemas", database_name, user_id, role,
                "SUCCESS", response_summary=f"{payload['schema_count']} schema(s)",
            )
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(exc, request_id, "list_allowed_schemas", database_name, user_role)

    # ---- tool 2 ------------------------------------------------------------

    def list_allowed_tables(
        self, database_name: str, schema_name: str, user_role: str | None = None
    ) -> dict[str, Any]:
        request_id = new_request_id()
        try:
            role, user_id = self._identity(user_role)
            payload = self.metadata.list_objects(
                database_name, schema_name, role, self._connection(database_name)
            )
            self._audit(
                request_id, "list_allowed_tables", database_name, user_id, role,
                "SUCCESS", response_summary=f"{payload['object_count']} object(s)",
            )
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(exc, request_id, "list_allowed_tables", database_name, user_role)

    # ---- tool 3 ------------------------------------------------------------

    def get_table_metadata(
        self,
        database_name: str,
        schema_name: str,
        table_name: str,
        user_role: str | None = None,
    ) -> dict[str, Any]:
        request_id = new_request_id()
        try:
            role, user_id = self._identity(user_role)
            payload = self.metadata.describe_object(
                database_name, schema_name, table_name, role, self._connection(database_name)
            )
            self._audit(
                request_id, "get_table_metadata", database_name, user_id, role,
                "SUCCESS",
                referenced_objects=[payload["qualified_name"]],
                response_summary=f"{payload['column_count']} column(s)",
            )
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(exc, request_id, "get_table_metadata", database_name, user_role)

    # ---- tool 4 ------------------------------------------------------------

    def search_data_dictionary(
        self, database_name: str, search_text: str, user_role: str | None = None
    ) -> dict[str, Any]:
        request_id = new_request_id()
        try:
            role, user_id = self._identity(user_role)
            payload = self.metadata.search(
                database_name, sanitize_free_text(search_text, 200), role
            )
            self._audit(
                request_id, "search_data_dictionary", database_name, user_id, role,
                "SUCCESS", user_question=search_text,
                response_summary=f"{payload['match_count']} match(es)",
            )
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(
                exc, request_id, "search_data_dictionary", database_name, user_role
            )

    # ---- tool 5 ------------------------------------------------------------

    def validate_sql(
        self, database_name: str, sql_text: str, user_role: str | None = None
    ) -> dict[str, Any]:
        request_id = new_request_id()
        try:
            role, user_id = self._identity(user_role)
            result = self.guard.validate(sql_text, database_name=database_name, role=role)
            if result.approved and result.sql_fingerprint:
                self.approvals.add(database_name, role.name, result.sql_fingerprint)

            payload = result.as_dict()
            if not role.show_sql:
                # A business user gets the verdict and the reasons, not the SQL.
                payload["rewritten_safe_sql"] = None
                payload["sql_visible_to_role"] = False
            else:
                payload["sql_visible_to_role"] = True
            payload["database"] = database_name.upper()
            payload["effective_row_limit"] = self.store.effective_max_rows(
                role, self.settings.max_rows
            )

            self._audit(
                request_id, "validate_sql", database_name, user_id, role,
                "SUCCESS" if result.approved else "REJECTED",
                sql=result.rewritten_safe_sql or sql_text,
                validation_status=result.validation_status,
                validation_errors=[e.code for e in result.validation_errors],
                referenced_objects=result.referenced_objects,
                response_summary=result.explanation[:500],
            )
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(exc, request_id, "validate_sql", database_name, user_role)

    # ---- tool 6 ------------------------------------------------------------

    def execute_readonly_sql(
        self,
        database_name: str,
        validated_sql: str,
        user_id: str | None = None,
        request_id: str | None = None,
        bind_parameters: dict[str, Any] | None = None,
        user_role: str | None = None,
    ) -> dict[str, Any]:
        request_id = request_id or new_request_id()
        role: Role | None = None
        resolved_user = user_id or "unknown"
        try:
            role, resolved_user = self._identity(user_role, user_id)
            result, connection = self._prepare_execution(database_name, validated_sql, role)
            payload = self._run_query(
                result, connection, role, bind_parameters, database_name
            )
            self._audit(
                request_id, "execute_readonly_sql", database_name, resolved_user, role,
                "SUCCESS",
                sql=result.rewritten_safe_sql or "",
                validation_status=result.validation_status,
                referenced_objects=result.referenced_objects,
                row_count=payload["row_count"],
                truncated=payload["truncated"],
                execution_ms=payload["execution_ms"],
                masked_columns=[m["column"] for m in payload["masked_columns"]],
                response_summary=f"{payload['row_count']} row(s) returned",
            )
            if not role.show_sql:
                payload["sql_executed"] = None
                payload["sql_visible_to_role"] = False
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._handle(
                exc, request_id, "execute_readonly_sql", database_name, user_role,
                user_id=resolved_user, role=role, sql=validated_sql,
            )

    def _prepare_execution(
        self, database_name: str, sql: str, role: Role
    ) -> tuple[ValidationResult, OracleConnection]:
        """Re-validate independently, then check the statement was pre-approved."""
        result = self.guard.validate(sql, database_name=database_name, role=role)
        if not result.approved:
            raise SqlValidationError(
                "The SQL failed safety validation and was not executed: "
                + "; ".join(e.message for e in result.validation_errors),
                next_steps=[
                    "Call validate_sql and use the rewritten_safe_sql it returns.",
                    "Restrict the query to approved objects and columns.",
                ],
                context={"validation_errors": [e.as_dict() for e in result.validation_errors]},
            )

        assert result.sql_fingerprint is not None
        if not role.allow_raw_sql and not self.approvals.is_approved(
            database_name, role.name, result.sql_fingerprint
        ):
            raise AccessDeniedError(
                f"Role '{role.name}' may only execute SQL that was approved by validate_sql "
                "in this session. Validate the statement first, then execute exactly the "
                "SQL that validate_sql returned.",
                next_steps=[
                    "Call validate_sql with this database and SQL.",
                    "Execute the rewritten_safe_sql value it returns, unchanged.",
                ],
            )

        connection = self.registry.get(database_name)

        if self.settings.max_plan_cost > 0 and result.rewritten_safe_sql:
            cost = connection.plan_cost(result.rewritten_safe_sql)
            if cost is not None and cost > self.settings.max_plan_cost:
                raise SqlValidationError(
                    f"The query's estimated cost ({cost}) exceeds the limit of "
                    f"{self.settings.max_plan_cost}.",
                    next_steps=[
                        "Add a more selective filter, such as a narrower date range.",
                        "Query a summarised reporting view instead.",
                    ],
                )
        return result, connection

    def _run_query(
        self,
        result: ValidationResult,
        connection: OracleConnection,
        role: Role,
        bind_parameters: dict[str, Any] | None,
        database_name: str,
    ) -> dict[str, Any]:
        sql = result.rewritten_safe_sql or ""
        binds = self._check_binds(result, bind_parameters)
        row_limit = result.applied_row_limit or self.store.effective_max_rows(
            role, self.settings.max_rows
        )

        columns, rows, truncated, elapsed_ms = connection.fetch(sql, binds, max_rows=row_limit)

        object_policy = None
        if len(result.referenced_objects) == 1:
            schema, _, name = result.referenced_objects[0].partition(".")
            object_policy = self.store.database(database_name).resolve_object(schema, name)

        column_policies = {}
        for fqn in result.referenced_objects:
            schema, _, name = fqn.partition(".")
            obj = self.store.database(database_name).resolve_object(schema, name)
            if obj:
                column_policies.update({c.name.upper(): c for c in obj.columns})

        masked_rows, report = self.masker.mask_rows(
            rows, role=role, object_policy=object_policy, column_policies=column_policies
        )

        warnings = list(result.warnings)
        if truncated:
            warnings.append(
                f"The result was capped at {row_limit} rows. Totals derived from these rows "
                "are lower bounds; use an aggregate query for exact counts."
            )
        if report.masked_columns:
            warnings.append(
                f"{len(report.masked_columns)} column(s) were masked for role '{role.name}'."
            )

        return {
            "database_source": self.registry.get(database_name).profile.display_name,
            "database": database_name.upper(),
            "columns": columns,
            "rows": masked_rows,
            "row_count": len(masked_rows),
            "truncated": truncated,
            "row_limit_applied": row_limit,
            "execution_ms": round(elapsed_ms, 1),
            "execution_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "referenced_objects": result.referenced_objects,
            "masked_columns": report.as_list(),
            "sql_executed": sql,
            "sql_visible_to_role": role.show_sql,
            "warnings": warnings,
        }

    def _check_binds(
        self, result: ValidationResult, bind_parameters: dict[str, Any] | None
    ) -> dict[str, Any]:
        supplied = {k.lstrip(":"): v for k, v in (bind_parameters or {}).items()}
        required = {name.lstrip(":") for name in result.bind_parameters}
        missing = required - set(supplied)
        if missing:
            raise SqlValidationError(
                f"The SQL declares bind parameter(s) {', '.join(sorted(missing))} but no "
                "value was supplied.",
                next_steps=["Pass every bind variable in bind_parameters."],
            )
        return {k: v for k, v in supplied.items() if k in required}

    # ---- tool 7 ------------------------------------------------------------

    def explain_query_result(
        self,
        user_question: str,
        sql_text: str = "",
        query_result: dict[str, Any] | list[dict[str, Any]] | None = None,
        table_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Turn a result set into pre-computed facts for the model to narrate."""
        request_id = new_request_id()
        try:
            rows, columns, truncated, row_limit, database, objects = _unpack_result(query_result)
            profile = profile_rows(rows, columns)
            observations = key_observations(profile, truncated, row_limit)
            quality = data_quality_flags(profile)

            answer_basis = (
                f"The query returned {profile['row_count']} row(s)."
                if profile["row_count"]
                else "The query returned no rows."
            )

            payload: dict[str, Any] = {
                "user_question": sanitize_free_text(user_question),
                "answer_basis": answer_basis,
                "key_observations": observations,
                "data_quality_flags": quality,
                "column_profile": profile["columns"],
                "assumptions": _assumptions(sql_text, truncated, row_limit),
                "data_source_used": {
                    "database": database or "unspecified",
                    "objects": objects,
                    "row_count": profile["row_count"],
                    "truncated": truncated,
                    "execution_timestamp": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    ),
                },
                "limitations": _limitations(truncated, row_limit, table_metadata),
            }
            if profile["row_count"] == 0:
                payload["empty_result_reasons"] = empty_result_reasons(sql_text, objects)
                payload["suggested_next_steps"] = [
                    "Widen the date range or remove one filter and re-run.",
                    "Use search_data_dictionary to confirm the right object holds this data.",
                    "Check the integration status objects if the records were expected today.",
                ]
            return self._ok(payload, request_id)
        except ChatbotError as exc:
            return self._fail(exc, request_id)

    # ---- tool 8 ------------------------------------------------------------

    def compare_onprem_and_atp_data(
        self,
        business_entity: str,
        matching_key: str,
        onprem_query: str,
        atp_query: str,
        user_role: str | None = None,
        compare_columns: list[str] | None = None,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        request_id = new_request_id()
        role: Role | None = None
        resolved_user = user_id or "unknown"
        try:
            role, resolved_user = self._identity(user_role, user_id)
            if not self.settings.reconciliation_enabled:
                raise AccessDeniedError(
                    "This server instance serves a single database, so it cannot compare "
                    "On-Prem with ATP.",
                    next_steps=[
                        "Connect to the reconciliation server (ORACLE_MCP_PROFILE=both).",
                        "Alternatively run both queries separately and compare the counts.",
                    ],
                )
            if not role.allow_reconciliation:
                raise AccessDeniedError(
                    f"Role '{role.name}' is not authorised to run cross-database "
                    "reconciliation.",
                    next_steps=["Ask an analyst or support user to run the comparison."],
                )

            # Both sides validate before either executes, so a rejected second
            # query cannot leave the first one already run.
            source_plan, source_conn = self._prepare_execution("ONPREM", onprem_query, role)
            target_plan, target_conn = self._prepare_execution("ATP", atp_query, role)

            source_payload = self._run_query(source_plan, source_conn, role, None, "ONPREM")
            target_payload = self._run_query(target_plan, target_conn, role, None, "ATP")

            comparison = compare_result_sets(
                business_entity=sanitize_free_text(business_entity, 120),
                matching_key=matching_key,
                source=SideResult(
                    database=source_payload["database_source"],
                    rows=source_payload["rows"],
                    row_count=source_payload["row_count"],
                    truncated=source_payload["truncated"],
                    execution_ms=source_payload["execution_ms"],
                    sql=source_plan.rewritten_safe_sql or "",
                ),
                target=SideResult(
                    database=target_payload["database_source"],
                    rows=target_payload["rows"],
                    row_count=target_payload["row_count"],
                    truncated=target_payload["truncated"],
                    execution_ms=target_payload["execution_ms"],
                    sql=target_plan.rewritten_safe_sql or "",
                ),
                compare_columns=compare_columns,
            )
            if role.show_sql:
                comparison["sql_executed"] = {
                    "onprem": source_plan.rewritten_safe_sql,
                    "atp": target_plan.rewritten_safe_sql,
                }

            summary = comparison["summary"]
            self._audit(
                request_id, "compare_onprem_and_atp_data", "ONPREM+ATP", resolved_user, role,
                "SUCCESS",
                sql=source_plan.rewritten_safe_sql or "",
                referenced_objects=(
                    source_plan.referenced_objects + target_plan.referenced_objects
                ),
                row_count=summary["source_row_count"] + summary["target_row_count"],
                response_summary=(
                    f"matched={summary['matched_records']} "
                    f"unmatched={summary['unmatched_records']}"
                ),
            )
            return self._ok(comparison, request_id)
        except ChatbotError as exc:
            return self._handle(
                exc, request_id, "compare_onprem_and_atp_data", "ONPREM+ATP", user_role,
                user_id=resolved_user, role=role,
            )

    # ---- audit helpers -----------------------------------------------------

    def _audit(
        self,
        request_id: str,
        tool_name: str,
        database_name: str,
        user_id: str,
        role: Role | None,
        status: str,
        **extra: Any,
    ) -> None:
        try:
            self.audit.record(
                build_event(
                    request_id=request_id,
                    tool_name=tool_name,
                    database_name=(database_name or "").upper(),
                    user_id=user_id,
                    user_role=role.name if role else "unresolved",
                    status=status,
                    **extra,
                )
            )
        except Exception:  # noqa: BLE001 - auditing must never break a request
            logger.exception("Audit record failed for %s", tool_name)

    def _handle(
        self,
        exc: ChatbotError,
        request_id: str,
        tool_name: str,
        database_name: str,
        user_role: str | None,
        *,
        user_id: str = "unknown",
        role: Role | None = None,
        sql: str = "",
    ) -> dict[str, Any]:
        logger.info("%s rejected: %s (%s)", tool_name, exc.code, database_name)
        self._audit(
            request_id, tool_name, database_name, user_id,
            role or _safe_role(self.store, user_role, self.settings),
            "ERROR",
            sql=sql,
            error_code=exc.code,
            error_message=str(exc)[:2000],
            validation_errors=[exc.code],
        )
        return self._fail(exc, request_id)


def _safe_role(store: PolicyStore, user_role: str | None, settings: Settings) -> Role | None:
    try:
        name = settings.pinned_role if settings.role_binding_mode == "env" else user_role
        return store.role(name)
    except ChatbotError:
        return None


def _unpack_result(
    query_result: dict[str, Any] | list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[str], bool, int, str, list[str]]:
    """Accept either a full execute_readonly_sql envelope or a bare row list."""
    if query_result is None:
        return [], [], False, 0, "", []
    if isinstance(query_result, list):
        rows = [r for r in query_result if isinstance(r, dict)]
        return rows, list(rows[0].keys()) if rows else [], False, 0, "", []
    rows = [r for r in (query_result.get("rows") or []) if isinstance(r, dict)]
    return (
        rows,
        query_result.get("columns") or (list(rows[0].keys()) if rows else []),
        bool(query_result.get("truncated", False)),
        int(query_result.get("row_limit_applied") or 0),
        str(query_result.get("database_source") or query_result.get("database") or ""),
        list(query_result.get("referenced_objects") or []),
    )


def _assumptions(sql_text: str, truncated: bool, row_limit: int) -> list[str]:
    assumptions: list[str] = []
    upper = (sql_text or "").upper()
    if "SYSDATE" in upper or "CURRENT_DATE" in upper:
        assumptions.append("'Today' is the database server date, not the user's local date.")
    if "TRUNC(" in upper:
        assumptions.append("Timestamps were truncated to whole days.")
    if " JOIN " in upper or "," in upper.split("FROM")[-1][:200]:
        assumptions.append(
            "Records were matched across objects using the join keys in the query; rows "
            "without a match on both sides are excluded."
        )
    if truncated:
        assumptions.append(
            f"Only the first {row_limit} rows were analysed because of the row cap."
        )
    if not assumptions:
        assumptions.append("No additional filters beyond those stated in the question.")
    return assumptions


def _limitations(
    truncated: bool, row_limit: int, table_metadata: dict[str, Any] | None
) -> list[str]:
    limitations: list[str] = []
    if truncated:
        limitations.append(
            f"The result was capped at {row_limit} rows, so counts are lower bounds."
        )
    if table_metadata and table_metadata.get("restricted_columns_hidden"):
        limitations.append(
            f"{table_metadata['restricted_columns_hidden']} column(s) are restricted for "
            "this role and were excluded from the analysis."
        )
    limitations.append(
        "Only objects approved for chatbot access were queried; data held elsewhere is "
        "not reflected."
    )
    limitations.append("Sensitive values are masked, so they cannot be reconciled in detail.")
    return limitations
