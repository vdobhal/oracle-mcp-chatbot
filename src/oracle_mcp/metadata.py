"""Schema and data-dictionary discovery.

Live metadata is read from the ``ALL_*`` dictionary views, which show only what
the read-only user has actually been granted. It is then intersected with the
policy allowlist, so a grant made outside the change process does not silently
widen what the chatbot can see.

Every dictionary query is fully bind-parameterised. These statements bypass the
SQL guard because they are fixed server-owned text, never user input.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .db import OracleConnection
from .errors import MetadataUnavailableError
from .policy import DatabasePolicy, ObjectPolicy, PolicyStore, Role, sensitivity_rank

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 300
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]{0,127}$")

_ROW_COUNT_SQL = """
    SELECT table_name, num_rows
      FROM all_tables
     WHERE owner = :owner
"""

_COLUMNS_SQL = """
    SELECT c.column_name,
           c.data_type,
           c.data_length,
           c.data_precision,
           c.data_scale,
           c.nullable,
           c.column_id,
           cc.comments
      FROM all_tab_columns c
      LEFT JOIN all_col_comments cc
             ON cc.owner = c.owner
            AND cc.table_name = c.table_name
            AND cc.column_name = c.column_name
     WHERE c.owner = :owner
       AND c.table_name = :table_name
     ORDER BY c.column_id
"""

_TABLE_COMMENT_SQL = """
    SELECT comments
      FROM all_tab_comments
     WHERE owner = :owner AND table_name = :table_name
"""

_PRIMARY_KEY_SQL = """
    SELECT cols.column_name, cols.position
      FROM all_constraints cons
      JOIN all_cons_columns cols
        ON cols.owner = cons.owner
       AND cols.constraint_name = cons.constraint_name
     WHERE cons.owner = :owner
       AND cons.table_name = :table_name
       AND cons.constraint_type = 'P'
     ORDER BY cols.position
"""

_FOREIGN_KEY_SQL = """
    SELECT cons.constraint_name,
           cols.column_name,
           r_cons.owner        AS referenced_owner,
           r_cons.table_name   AS referenced_table,
           r_cols.column_name  AS referenced_column
      FROM all_constraints cons
      JOIN all_cons_columns cols
        ON cols.owner = cons.owner
       AND cols.constraint_name = cons.constraint_name
      JOIN all_constraints r_cons
        ON r_cons.owner = cons.r_owner
       AND r_cons.constraint_name = cons.r_constraint_name
      JOIN all_cons_columns r_cols
        ON r_cols.owner = r_cons.owner
       AND r_cols.constraint_name = r_cons.constraint_name
       AND r_cols.position = cols.position
     WHERE cons.owner = :owner
       AND cons.table_name = :table_name
       AND cons.constraint_type = 'R'
     ORDER BY cons.constraint_name, cols.position
"""


_ALL_SCHEMAS_SQL = """
    SELECT DISTINCT owner
      FROM all_objects
     WHERE object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
     ORDER BY owner
"""

_SCHEMA_OBJECTS_SQL = """
    SELECT object_name, object_type
      FROM all_objects
     WHERE owner = :owner
       AND object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
     ORDER BY object_name
"""

_SEARCH_OBJECTS_SQL = """
    SELECT owner, object_name, object_type
      FROM all_objects
     WHERE object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
       AND ({predicate})
       AND ROWNUM <= :row_limit
     ORDER BY owner, object_name
"""

_SEARCH_COLUMNS_SQL = """
    SELECT owner, table_name, column_name, data_type
      FROM all_tab_columns
     WHERE ({predicate})
       AND ROWNUM <= :row_limit
     ORDER BY owner, table_name, column_name
"""

_COLUMN_NAMES_SQL = """
    SELECT column_name
      FROM all_tab_columns
     WHERE owner = :owner AND table_name = :table_name
     ORDER BY column_id
"""

# Dictionary reads are capped so a database with a very large catalogue cannot
# turn a single tool call into an unbounded fetch.
_MAX_DICTIONARY_ROWS = 5000


def _safe_identifier(value: str, label: str) -> str:
    """Guard the dictionary queries themselves against injection via bind values."""
    candidate = (value or "").strip().upper()
    if not _IDENTIFIER.match(candidate):
        raise MetadataUnavailableError(
            f"{label} {value!r} is not a valid Oracle identifier.",
            next_steps=["Use list_allowed_tables to obtain exact object names."],
        )
    return candidate


@dataclass
class _CacheEntry:
    value: Any
    expires_at: float


class DataDictionary:
    """Data-dictionary reads for policies that discover rather than declare.

    Backs wildcard-schema databases and allowlisted objects with no declared
    column list. Everything it returns is filtered by Oracle itself through the
    ``ALL_*`` views, so it can only ever report what the chatbot's own read-only
    account has been granted.

    Failures return empty rather than raising. An empty result means "not found",
    which the policy layer turns into a denial, so a dictionary outage fails
    closed instead of opening access.
    """

    def __init__(self, registry: Any) -> None:
        self.registry = registry
        self._cache: dict[tuple[str, ...], _CacheEntry] = {}

    def clear_cache(self) -> None:
        self._cache.clear()

    def _cached(self, key: tuple[str, ...], producer: Any) -> Any:
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit is not None and hit.expires_at > now:
            return hit.value
        value = producer()
        self._cache[key] = _CacheEntry(value, now + _CACHE_TTL_SECONDS)
        return value

    def _fetch(self, database: str, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            connection = self.registry.get(database)
        except Exception as exc:  # noqa: BLE001 - unavailable DB must not open access
            logger.warning("Dictionary lookup on %s unavailable: %s", database, type(exc).__name__)
            return []
        try:
            _, rows, _, _ = connection.fetch(sql, params, max_rows=_MAX_DICTIONARY_ROWS)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Dictionary query on %s failed: %s", database, type(exc).__name__)
            return []
        return rows

    def list_schemas(self, database: str) -> tuple[str, ...]:
        def _load() -> tuple[str, ...]:
            rows = self._fetch(database, _ALL_SCHEMAS_SQL, {})
            return tuple(str(r["OWNER"]).upper() for r in rows if r.get("OWNER"))

        return self._cached(("schemas", database), _load)

    def list_objects(self, database: str, schema: str) -> tuple[tuple[str, str], ...]:
        owner = (schema or "").strip().upper()
        if not _IDENTIFIER.match(owner):
            return ()

        def _load() -> tuple[tuple[str, str], ...]:
            rows = self._fetch(database, _SCHEMA_OBJECTS_SQL, {"owner": owner})
            return tuple(
                (str(r["OBJECT_NAME"]).upper(), str(r.get("OBJECT_TYPE") or "TABLE").upper())
                for r in rows
                if r.get("OBJECT_NAME")
            )

        return self._cached(("objects", database, owner), _load)

    def _search(
        self,
        database: str,
        sql_template: str,
        column_expr: str,
        terms: list[str],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Term search pushed into the dictionary rather than enumerated in Python.

        A wildcard database may hold thousands of objects, so matching them one
        schema at a time would mean a dictionary round trip per schema. The terms
        are bound, never interpolated; only the number of placeholders varies, and
        ``column_expr`` is a server-owned literal rather than caller input.
        """
        if not terms:
            return []
        binds = {f"t{i}": f"%{term.lower()}%" for i, term in enumerate(terms[:5])}
        predicate = " OR ".join(f"LOWER({column_expr}) LIKE :{name}" for name in binds)
        sql = sql_template.replace("{predicate}", predicate)
        return self._fetch(database, sql, {**binds, "row_limit": int(limit)})

    def search_objects(self, database: str, terms: list[str], limit: int) -> list[dict[str, Any]]:
        return self._search(database, _SEARCH_OBJECTS_SQL, "object_name", terms, limit)

    def search_columns(self, database: str, terms: list[str], limit: int) -> list[dict[str, Any]]:
        return self._search(database, _SEARCH_COLUMNS_SQL, "column_name", terms, limit)

    def list_columns(self, database: str, schema: str, object_name: str) -> tuple[str, ...]:
        owner = (schema or "").strip().upper()
        table = (object_name or "").strip().upper()
        if not _IDENTIFIER.match(owner) or not _IDENTIFIER.match(table):
            return ()

        def _load() -> tuple[str, ...]:
            rows = self._fetch(
                database, _COLUMN_NAMES_SQL, {"owner": owner, "table_name": table}
            )
            return tuple(str(r["COLUMN_NAME"]).upper() for r in rows if r.get("COLUMN_NAME"))

        return self._cached(("columns", database, owner, table), _load)


class MetadataService:
    """Reads live metadata and merges it with the business descriptions in policy."""

    def __init__(self, store: PolicyStore, dictionary: DataDictionary | None = None) -> None:
        self.store = store
        self.dictionary = dictionary
        self._cache: dict[tuple[str, ...], _CacheEntry] = {}

    def _cached(self, key: tuple[str, ...], producer: Any) -> Any:
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit is not None and hit.expires_at > now:
            return hit.value
        value = producer()
        self._cache[key] = _CacheEntry(value, now + _CACHE_TTL_SECONDS)
        return value

    def clear_cache(self) -> None:
        self._cache.clear()

    # ---- schemas -----------------------------------------------------------

    def list_schemas(self, database_name: str, role: Role) -> dict[str, Any]:
        policy: DatabasePolicy = self.store.database(database_name)
        schemas = self.store.allowed_schemas(database_name, role)
        return {
            "database": policy.database,
            "display_name": policy.display_name,
            "description": policy.description,
            "user_role": role.name,
            "role_clearance": role.clearance,
            "schema_count": len(schemas),
            "schemas": [
                {
                    "schema_name": s.name,
                    "description": s.description,
                    "business_domain": s.business_domain,
                    # Counting objects in a discovered schema means a dictionary
                    # scan per schema, so it is deferred to list_allowed_tables.
                    "approved_object_count": (
                        len([o for o in s.objects if o.rank <= role.clearance_rank])
                        if s.objects or not policy.discovery_enabled
                        else None
                    ),
                }
                for s in schemas
            ],
            "notes": (
                [
                    (
                        "This database exposes every schema the read-only account can "
                        "read; the database grant is the effective allowlist."
                        if policy.allow_all_schemas and not policy.discovered_schemas
                        else "This database exposes a fixed set of schemas; their objects "
                        "are discovered from the data dictionary."
                    ),
                    "Call list_allowed_tables for a schema to see its objects.",
                ]
                if policy.discovery_enabled
                else []
            ),
        }

    # ---- objects -----------------------------------------------------------

    def list_objects(
        self,
        database_name: str,
        schema_name: str,
        role: Role,
        connection: OracleConnection | None = None,
    ) -> dict[str, Any]:
        policy = self.store.database(database_name)
        schema = policy.schema(schema_name)
        target = (schema_name or "").strip().upper()
        # A schema is reachable either because the YAML declares it, or because
        # discovery covers it. Excluded schemas are never reachable.
        reachable = (schema is not None or policy.is_discoverable(target)) and (
            not policy.is_excluded_schema(target)
        )
        if not role.can_see_schema(policy.database, target) or not reachable:
            raise MetadataUnavailableError(
                f"Schema {target} is not approved for role '{role.name}' on "
                f"{policy.display_name}.",
                next_steps=["Call list_allowed_schemas to see what your role can access."],
            )

        visible = self.store.allowed_objects(database_name, role, schema=target)
        if not visible and schema is None:
            raise MetadataUnavailableError(
                f"Schema {target} holds no objects readable by this connection on "
                f"{policy.display_name}.",
                next_steps=["Call list_allowed_schemas to see what your role can access."],
            )
        estimates = self._row_estimates(connection, target, visible)

        return {
            "database": policy.database,
            "schema_name": target,
            "schema_description": schema.description if schema else "Discovered schema.",
            "user_role": role.name,
            "object_count": len(visible),
            "objects": [
                {
                    "table_name": obj.name,
                    "qualified_name": obj.fqn,
                    "object_type": obj.object_type,
                    "table_description": obj.description,
                    "business_domain": obj.business_domain,
                    "data_sensitivity": obj.sensitivity,
                    # Resolving this for an undeclared object costs a dictionary
                    # round trip each; get_table_metadata reports it instead.
                    "approved_column_count": (
                        len(obj.columns_visible_to(role.clearance_rank))
                        if obj.columns_declared
                        else None
                    ),
                    "estimated_row_count": estimates.get(obj.name),
                    "large_table": obj.large_table,
                    "filter_required": obj.require_filter,
                }
                for obj in visible
            ],
            "notes": [
                "Row counts are optimizer estimates from ALL_TABLES and may be stale.",
                "Only objects approved for your role are listed.",
            ],
        }

    def _row_estimates(
        self,
        connection: OracleConnection | None,
        schema: str,
        objects: list[ObjectPolicy],
    ) -> dict[str, int | None]:
        if connection is None or not objects:
            return {}

        def _load() -> dict[str, int | None]:
            # One query for the whole schema, not one per object. A discovered
            # schema can hold hundreds of tables, and a round trip each turns a
            # single tool call into minutes against a remote database.
            try:
                _, rows, _, _ = connection.fetch(
                    _ROW_COUNT_SQL, {"owner": schema}, max_rows=_MAX_DICTIONARY_ROWS
                )
            except Exception as exc:  # noqa: BLE001 - estimates are best effort
                logger.debug("Row estimates unavailable for %s: %s", schema, type(exc).__name__)
                return {}
            return {
                str(r["TABLE_NAME"]): r.get("NUM_ROWS") for r in rows if r.get("TABLE_NAME")
            }

        return self._cached(("rowcounts", connection.database_name, schema), _load)

    # ---- table metadata ----------------------------------------------------

    def describe_object(
        self,
        database_name: str,
        schema_name: str | None,
        table_name: str,
        role: Role,
        connection: OracleConnection | None = None,
    ) -> dict[str, Any]:
        obj = self.store.authorize_object(database_name, schema_name, table_name, role)
        policy = self.store.database(database_name)
        owner = _safe_identifier(obj.schema, "Schema")
        table = _safe_identifier(obj.name, "Table")

        live = self._live_columns(connection, owner, table)
        clearance = role.clearance_rank

        columns: list[dict[str, Any]] = []
        restricted: list[str] = []
        for col in self.store.columns_for(database_name, obj):
            if col.rank > clearance:
                restricted.append(col.name)
                continue
            info = live["columns"].get(col.name, {})
            columns.append(
                {
                    "column_name": col.name,
                    "data_type": info.get("data_type", "UNKNOWN"),
                    "length": info.get("length"),
                    "precision": info.get("precision"),
                    "scale": info.get("scale"),
                    "nullable": info.get("nullable"),
                    "position": info.get("position"),
                    "is_primary_key": col.name in live["primary_key"],
                    "business_description": col.description or info.get("comment", ""),
                    "data_sensitivity": col.sensitivity,
                }
            )

        foreign_keys = [
            fk
            for fk in live["foreign_keys"]
            if fk["column_name"] not in restricted
        ]

        return {
            "database": policy.database,
            "schema_name": obj.schema,
            "table_name": obj.name,
            "qualified_name": obj.fqn,
            "object_type": obj.object_type,
            "table_description": obj.description or live.get("comment", ""),
            "business_domain": obj.business_domain,
            "data_sensitivity": obj.sensitivity,
            "metadata_source": live["source"],
            "column_count": len(columns),
            "columns": columns,
            "primary_key": [c for c in live["primary_key"] if c not in restricted],
            "foreign_keys": foreign_keys,
            "restricted_columns_hidden": len(restricted),
            "filter_required": obj.require_filter,
            "notes": (
                [
                    f"{len(restricted)} column(s) are classified above role "
                    f"'{role.name}' clearance and are not listed."
                ]
                if restricted
                else []
            ),
        }

    def _live_columns(
        self, connection: OracleConnection | None, owner: str, table: str
    ) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "columns": {},
            "primary_key": [],
            "foreign_keys": [],
            "comment": "",
            "source": "policy_only",
        }
        if connection is None:
            return empty

        def _load() -> dict[str, Any]:
            binds = {"owner": owner, "table_name": table}
            try:
                _, col_rows, _, _ = connection.fetch(_COLUMNS_SQL, binds, max_rows=2000)
                _, pk_rows, _, _ = connection.fetch(_PRIMARY_KEY_SQL, binds, max_rows=100)
                _, fk_rows, _, _ = connection.fetch(_FOREIGN_KEY_SQL, binds, max_rows=200)
                _, tc_rows, _, _ = connection.fetch(_TABLE_COMMENT_SQL, binds, max_rows=1)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Live metadata unavailable for %s.%s: %s", owner, table, type(exc).__name__
                )
                return empty
            if not col_rows:
                return empty

            columns = {
                str(r["COLUMN_NAME"]).upper(): {
                    "data_type": r.get("DATA_TYPE"),
                    "length": r.get("DATA_LENGTH"),
                    "precision": r.get("DATA_PRECISION"),
                    "scale": r.get("DATA_SCALE"),
                    "nullable": r.get("NULLABLE") == "Y",
                    "position": r.get("COLUMN_ID"),
                    "comment": r.get("COMMENTS") or "",
                }
                for r in col_rows
            }
            return {
                "columns": columns,
                "primary_key": [str(r["COLUMN_NAME"]).upper() for r in pk_rows],
                "foreign_keys": [
                    {
                        "constraint_name": r.get("CONSTRAINT_NAME"),
                        "column_name": str(r.get("COLUMN_NAME", "")).upper(),
                        "references": (
                            f"{r.get('REFERENCED_OWNER')}.{r.get('REFERENCED_TABLE')}"
                            f".{r.get('REFERENCED_COLUMN')}"
                        ),
                    }
                    for r in fk_rows
                ],
                "comment": (tc_rows[0].get("COMMENTS") if tc_rows else "") or "",
                "source": "database",
            }

        return self._cached(("columns", connection.database_name, owner, table), _load)

    # ---- search ------------------------------------------------------------

    def _search_dictionary(
        self,
        policy: DatabasePolicy,
        terms: list[str],
        search_text: str,
        role: Role,
        limit: int,
    ) -> dict[str, Any]:
        """Search a wildcard database straight through the data dictionary.

        Column sensitivity is inferred from the masking rules, because a
        discovered column has no hand-assigned classification. Columns the role
        cannot clear are dropped from the results rather than listed, so the
        search itself does not disclose that a restricted column exists.
        """
        if self.dictionary is None:
            raise MetadataUnavailableError(
                f"{policy.display_name} requires data-dictionary search, which is "
                "not available on this server.",
                next_steps=["Retry once the database connection is restored."],
            )

        def _visible(owner: str, object_name: str) -> bool:
            # The dictionary search spans the whole instance, so results must be
            # filtered back down to the schemas this policy actually exposes.
            # Excluded objects are dropped here too; search is a discovery path
            # like any other and must not surface what listing hides.
            return (
                role.can_see_schema(policy.database, owner)
                and policy.is_discoverable(owner)
                and not policy.is_excluded_object(object_name)
            )

        table_hits = [
            {
                "qualified_name": f"{r['OWNER']}.{r['OBJECT_NAME']}",
                "schema_name": r["OWNER"],
                "table_name": r["OBJECT_NAME"],
                "object_type": r.get("OBJECT_TYPE", "TABLE"),
                "business_description": "",
                "business_domain": policy.domain_for(str(r["OBJECT_NAME"])) or r["OWNER"],
                "data_sensitivity": "INTERNAL",
                "confidence_score": round(_score(terms, str(r["OBJECT_NAME"]), "", ""), 3),
            }
            for r in self.dictionary.search_objects(policy.database, terms, limit * 4)
            if _visible(str(r.get("OWNER", "")), str(r.get("OBJECT_NAME", "")))
        ]

        column_hits = []
        for r in self.dictionary.search_columns(policy.database, terms, limit * 4):
            owner = str(r.get("OWNER", ""))
            if not _visible(owner, str(r.get("TABLE_NAME", ""))):
                continue
            column_name = str(r["COLUMN_NAME"])
            sensitivity = self.store.infer_column_sensitivity(column_name)
            if sensitivity_rank(sensitivity) > role.clearance_rank:
                continue
            column_hits.append(
                {
                    "qualified_name": f"{owner}.{r['TABLE_NAME']}.{column_name}",
                    "schema_name": owner,
                    "table_name": r["TABLE_NAME"],
                    "column_name": column_name,
                    "business_description": "",
                    "data_sensitivity": sensitivity,
                    "confidence_score": round(_score(terms, column_name, "", ""), 3),
                }
            )

        table_hits.sort(key=lambda h: (-h["confidence_score"], h["qualified_name"]))
        column_hits.sort(key=lambda h: (-h["confidence_score"], h["qualified_name"]))

        return {
            "database": policy.database,
            "search_text": search_text,
            "user_role": role.name,
            "matching_tables": table_hits[:limit],
            "matching_columns": column_hits[:limit],
            "match_count": len(table_hits) + len(column_hits),
            "notes": [
                "Matched on object and column names in the data dictionary; this "
                "database has no curated business descriptions.",
                "Sensitivity is inferred from column naming rules, not a data steward's "
                "classification, so confirm before sharing results widely.",
            ],
        }

    def search(
        self, database_name: str, search_text: str, role: Role, limit: int = 25
    ) -> dict[str, Any]:
        policy = self.store.database(database_name)
        terms = [t for t in re.split(r"[^A-Za-z0-9]+", (search_text or "").lower()) if len(t) > 1]
        if not terms:
            raise MetadataUnavailableError(
                "Provide at least one search term of two or more characters.",
                next_steps=["Try a business term such as 'customer', 'contract' or 'tax'."],
            )

        table_hits: list[dict[str, Any]] = []
        column_hits: list[dict[str, Any]] = []

        if policy.discovery_enabled:
            return self._search_dictionary(policy, terms, search_text, role, limit)

        for obj in self.store.allowed_objects(database_name, role):
            table_score = _score(terms, obj.name, obj.description, obj.business_domain)
            if table_score > 0:
                table_hits.append(
                    {
                        "qualified_name": obj.fqn,
                        "schema_name": obj.schema,
                        "table_name": obj.name,
                        "object_type": obj.object_type,
                        "business_description": obj.description,
                        "business_domain": obj.business_domain,
                        "data_sensitivity": obj.sensitivity,
                        "confidence_score": round(table_score, 3),
                    }
                )
            for col in obj.columns_visible_to(role.clearance_rank):
                col_score = _score(terms, col.name, col.description, "")
                if col_score > 0:
                    column_hits.append(
                        {
                            "qualified_name": f"{obj.fqn}.{col.name}",
                            "schema_name": obj.schema,
                            "table_name": obj.name,
                            "column_name": col.name,
                            "business_description": col.description,
                            "data_sensitivity": col.sensitivity,
                            "confidence_score": round(col_score, 3),
                        }
                    )

        table_hits.sort(key=lambda h: (-h["confidence_score"], h["qualified_name"]))
        column_hits.sort(key=lambda h: (-h["confidence_score"], h["qualified_name"]))

        return {
            "database": policy.database,
            "search_text": search_text,
            "user_role": role.name,
            "matching_tables": table_hits[:limit],
            "matching_columns": column_hits[:limit],
            "match_count": len(table_hits) + len(column_hits),
            "notes": (
                ["No approved object matched. The data may not be exposed to the chatbot."]
                if not table_hits and not column_hits
                else [
                    "Confidence reflects term overlap with approved metadata only, "
                    "not statistical relevance."
                ]
            ),
        }


def _score(terms: list[str], name: str, description: str, domain: str) -> float:
    """Term overlap weighted by where the match lands.

    Name matches dominate description matches, and an exact name match scores
    highest, so ``EA_CONTRACT_ID`` outranks a table that merely mentions
    contracts in prose.
    """
    name_l = (name or "").lower()
    name_tokens = set(re.split(r"[^a-z0-9]+", name_l))
    haystack = f"{description} {domain}".lower()

    score = 0.0
    for term in terms:
        if term == name_l:
            score += 1.0
        elif term in name_tokens:
            score += 0.7
        elif term in name_l:
            score += 0.45
        if term in haystack:
            score += 0.2
    return min(score / max(len(terms), 1), 1.0)
