"""SQL guardrails.

The central control. Its design assumption is that the SQL string is hostile:
it may have been written by a jailbroken model, or lifted from a
prompt-injection payload stored in a database column.

The load-bearing decision is that **the text the user supplied is never the text
that runs**. Input is parsed into an AST, the AST is inspected and rewritten,
and the SQL that reaches Oracle is regenerated from that AST. Comment tricks,
whitespace tricks, unicode padding and stacked statements cannot survive the
round trip, because only node types the validator recognised are re-emitted.

Order of checks (each fails closed):

1. Shape       - length, control characters, statement count.
2. Parse       - unparseable input is rejected, never passed through.
3. Node type   - root must be a query; no DML/DDL node anywhere in the tree.
4. Identifiers - dangerous packages, dictionary views, database links.
5. Allowlist   - every table resolves to an approved object for the role.
6. Columns     - explicit column references are checked against clearance.
7. Shape rules - cartesian joins, unfiltered scans of large tables.
8. Rewrite     - row cap injected or clamped; hints stripped.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Literal

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from .errors import ChatbotError
from .policy import ColumnPolicy, ObjectPolicy, PolicyStore, Role

DIALECT = "oracle"

# Node types that must never appear anywhere in the tree, including nested in a
# subquery or CTE. exp.Command is sqlglot's fallback for statements it does not
# model (ALTER SESSION, many PL/SQL forms), so treating it as fatal keeps
# unknown syntax from reaching the database.
FORBIDDEN_NODES: tuple[tuple[type[exp.Expression], str], ...] = (
    (exp.Insert, "INSERT"),
    (exp.Update, "UPDATE"),
    (exp.Delete, "DELETE"),
    (exp.Merge, "MERGE"),
    (exp.Drop, "DROP"),
    (exp.Create, "CREATE"),
    (exp.Alter, "ALTER"),
    (exp.TruncateTable, "TRUNCATE"),
    (exp.Grant, "GRANT"),
    (exp.Revoke, "REVOKE"),
    (exp.Transaction, "transaction control"),
    (exp.Commit, "COMMIT"),
    (exp.Rollback, "ROLLBACK"),
    (exp.Use, "USE"),
    (exp.Set, "SET"),
    (exp.Copy, "COPY"),
    (exp.Into, "SELECT ... INTO"),
    (exp.Lock, "FOR UPDATE"),
    (exp.Command, "unrecognised or unsupported statement"),
)

# Applied to the regenerated, comment-free SQL.
BLOCKED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bDBMS_[A-Z0-9_]+", "DBMS_* package call"),
    (r"\bUTL_[A-Z0-9_]+", "UTL_* package call (network/file access)"),
    (r"\bOWA_[A-Z0-9_]+", "OWA_* package call"),
    (r"\bHTTP(?:S)?URITYPE\b", "URI type (outbound network access)"),
    (r"\bDBURITYPE\b", "URI type (outbound network access)"),
    (r"\bXDBURITYPE\b", "URI type (outbound network access)"),
    (r"\bSYS\s*\.", "SYS schema access"),
    (r"\bSYSTEM\s*\.", "SYSTEM schema access"),
    (r"\b(?:CTXSYS|MDSYS|ORDSYS|LBACSYS|WMSYS|OUTLN|XDB)\s*\.", "Oracle-internal schema access"),
    (r"\b(?:V|GV|X)\$[A-Z0-9_]+", "V$/GV$/X$ dynamic performance view"),
    (r"\bEXECUTE\s+IMMEDIATE\b", "dynamic SQL"),
    (r"\b(?:DECLARE|BEGIN)\b", "anonymous PL/SQL block"),
    (r"\bNEXTVAL\b", "sequence NEXTVAL (mutates database state)"),
    (r"\bSYS_CONTEXT\s*\(", "session context introspection"),
    (r"\bSYS_GUID\s*\(", "internal identifier generation"),
    (r"@\s*[A-Za-z_][A-Za-z0-9_$#.]*", "database link reference"),
    (r"\bJAVA\s+(?:SOURCE|CLASS)\b", "Java stored code"),
    (r"\bAS\s+SYSDBA\b", "privileged connection request"),
)

_COMPILED_BLOCKED = tuple((re.compile(p, re.IGNORECASE), label) for p, label in BLOCKED_PATTERNS)

# Characters used to smuggle payloads past naive scanners. Rejected outright.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class ValidationError:
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class ValidationResult:
    """Outcome of validating one statement."""

    validation_status: Literal["APPROVED", "REJECTED"]
    validation_errors: list[ValidationError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rewritten_safe_sql: str | None = None
    sql_fingerprint: str | None = None
    referenced_objects: list[str] = field(default_factory=list)
    applied_row_limit: int | None = None
    is_aggregate: bool = False
    bind_parameters: list[str] = field(default_factory=list)
    explanation: str = ""

    @property
    def approved(self) -> bool:
        return self.validation_status == "APPROVED"

    def as_dict(self) -> dict[str, Any]:
        return {
            "validation_status": self.validation_status,
            "validation_errors": [e.as_dict() for e in self.validation_errors],
            "warnings": self.warnings,
            "rewritten_safe_sql": self.rewritten_safe_sql,
            "sql_fingerprint": self.sql_fingerprint,
            "referenced_objects": self.referenced_objects,
            "applied_row_limit": self.applied_row_limit,
            "is_aggregate": self.is_aggregate,
            "bind_parameters": self.bind_parameters,
            "explanation": self.explanation,
        }


def fingerprint(sql: str) -> str:
    return hashlib.sha256(sql.strip().encode("utf-8")).hexdigest()


def redact_sql_literals(sql: str) -> str:
    """Replace literal values with ``?`` so audit records carry shape, not data.

    A ``WHERE TAX_ID = '123-45-6789'`` predicate would otherwise write the very
    value the masking layer just suppressed into the audit log.
    """
    try:
        tree = sqlglot.parse_one(sql, dialect=DIALECT)
    except (ParseError, TokenError):
        return re.sub(r"'[^']*'", "'?'", sql)
    if tree is None:
        return "?"

    def _scrub(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Literal):
            return exp.Literal.string("?") if node.is_string else exp.Literal.number(0)
        return node

    return tree.transform(_scrub).sql(dialect=DIALECT, comments=False)


class SqlGuard:
    """Validates and rewrites a single SELECT statement."""

    def __init__(
        self,
        store: PolicyStore,
        *,
        max_rows: int,
        max_sql_length: int = 20_000,
        allow_cartesian: bool = False,
    ) -> None:
        self.store = store
        self.max_rows = max_rows
        self.max_sql_length = max_sql_length
        self.allow_cartesian = allow_cartesian

    # ---- entry point -------------------------------------------------------

    def validate(self, sql_text: str, *, database_name: str, role: Role) -> ValidationResult:
        errors: list[ValidationError] = []
        warnings: list[str] = []

        normalized = self._normalize(sql_text, errors)
        if errors:
            return self._reject(errors)

        statements = self._parse(normalized, errors)
        if errors or not statements:
            return self._reject(errors)

        tree = statements[0]

        self._check_node_types(tree, errors)
        if errors:
            return self._reject(errors)

        tree = self._strip_hints(tree)

        # Regenerate before pattern scanning: comments are gone and syntax is
        # canonical, so obfuscation cannot hide an identifier from the scan.
        canonical = tree.sql(dialect=DIALECT, comments=False)
        self._check_blocked_patterns(canonical, errors)
        if errors:
            return self._reject(errors)

        objects = self._resolve_objects(tree, database_name, role, errors)
        if errors:
            return self._reject(errors)

        self._check_columns(tree, objects, role, errors, warnings)
        self._check_cartesian(tree, role, errors)
        is_aggregate = self._is_aggregate(tree)
        self._check_required_filters(tree, objects, is_aggregate, errors)
        if errors:
            return self._reject(errors)

        effective_limit = self.store.effective_max_rows(role, self.max_rows)
        tree, applied_limit, limit_notes = self._apply_row_limit(
            tree, effective_limit, is_aggregate
        )
        warnings.extend(limit_notes)

        tree = self._expand_star(tree, objects, role, warnings, database_name)

        safe_sql = tree.sql(dialect=DIALECT, comments=False, pretty=False)
        binds = sorted({p.name or p.sql(dialect=DIALECT) for p in tree.find_all(exp.Placeholder)})

        return ValidationResult(
            validation_status="APPROVED",
            validation_errors=[],
            warnings=warnings,
            rewritten_safe_sql=safe_sql,
            sql_fingerprint=fingerprint(safe_sql),
            referenced_objects=sorted(obj.fqn for obj in objects.values()),
            applied_row_limit=applied_limit,
            is_aggregate=is_aggregate,
            bind_parameters=binds,
            explanation=self._explain(objects, applied_limit, is_aggregate, warnings),
        )

    # ---- 1. shape ----------------------------------------------------------

    def _normalize(self, sql_text: str, errors: list[ValidationError]) -> str:
        if not sql_text or not sql_text.strip():
            errors.append(ValidationError("EMPTY_SQL", "No SQL was supplied."))
            return ""

        # NFKC first: it folds fullwidth and other lookalike forms into ASCII, so
        # a homoglyph SELECT cannot masquerade as an unrecognised keyword.
        text = unicodedata.normalize("NFKC", sql_text).strip()

        if _CONTROL_CHARS.search(text):
            errors.append(
                ValidationError(
                    "CONTROL_CHARACTERS",
                    "The SQL contains control characters, which are not permitted.",
                )
            )
        if len(text) > self.max_sql_length:
            errors.append(
                ValidationError(
                    "SQL_TOO_LONG",
                    f"The SQL is {len(text)} characters; the limit is {self.max_sql_length}.",
                )
            )
        return text.rstrip().rstrip(";").strip()

    # ---- 2. parse ----------------------------------------------------------

    def _parse(self, sql: str, errors: list[ValidationError]) -> list[exp.Expression]:
        try:
            statements = [s for s in sqlglot.parse(sql, dialect=DIALECT) if s is not None]
        except (ParseError, TokenError) as exc:
            # Fail closed. PL/SQL blocks and stacked-statement payloads land here.
            errors.append(
                ValidationError(
                    "SQL_PARSE_FAILED",
                    f"The SQL could not be parsed as a single Oracle SELECT statement: "
                    f"{str(exc).splitlines()[0]}",
                )
            )
            return []

        if not statements:
            errors.append(ValidationError("EMPTY_SQL", "No executable statement was found."))
            return []
        if len(statements) > 1:
            errors.append(
                ValidationError(
                    "MULTIPLE_STATEMENTS",
                    f"{len(statements)} statements were supplied. Exactly one SELECT is allowed.",
                )
            )
            return []
        return statements

    # ---- 3. node types -----------------------------------------------------

    def _check_node_types(self, tree: exp.Expression, errors: list[ValidationError]) -> None:
        root = tree.unnest() if isinstance(tree, exp.Subquery) else tree
        if not isinstance(root, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
            errors.append(
                ValidationError(
                    "NOT_A_SELECT",
                    f"Only SELECT statements are permitted; this is a "
                    f"{type(root).__name__.upper()} statement.",
                )
            )
            return
        for node_type, label in FORBIDDEN_NODES:
            if tree.find(node_type) is not None:
                errors.append(
                    ValidationError(
                        "FORBIDDEN_STATEMENT_TYPE",
                        f"{label} is not permitted. This chatbot is read-only.",
                    )
                )

    def _strip_hints(self, tree: exp.Expression) -> exp.Expression:
        """Remove optimizer hints: they are attacker-controlled plan steering."""
        for node in list(tree.find_all(exp.Hint)):
            node.pop()
        if isinstance(tree, exp.Select) and tree.args.get("hint"):
            tree.set("hint", None)
        return tree

    # ---- 4. identifiers ----------------------------------------------------

    def _check_blocked_patterns(self, sql: str, errors: list[ValidationError]) -> None:
        for pattern, label in _COMPILED_BLOCKED:
            match = pattern.search(sql)
            if match:
                errors.append(
                    ValidationError(
                        "BLOCKED_CONSTRUCT",
                        f"The SQL references {label}, which is blocked "
                        f"(matched {match.group(0)[:40]!r}).",
                    )
                )

    # ---- 5. allowlist ------------------------------------------------------

    def _local_names(self, tree: exp.Expression) -> set[str]:
        """CTE names and derived-table aliases resolve inside the query, not the schema."""
        names = {cte.alias_or_name.upper() for cte in tree.find_all(exp.CTE)}
        for subquery in tree.find_all(exp.Subquery):
            if subquery.alias:
                names.add(subquery.alias.upper())
        return names

    def _resolve_objects(
        self,
        tree: exp.Expression,
        database_name: str,
        role: Role,
        errors: list[ValidationError],
    ) -> dict[str, ObjectPolicy]:
        """Map every real table reference to an approved object.

        Keys are both the alias and the bare name so column resolution can look
        up either form.
        """
        local = self._local_names(tree)
        resolved: dict[str, ObjectPolicy] = {}

        for table in tree.find_all(exp.Table):
            name = table.name.upper()
            schema = (table.db or "").upper()
            if not schema and name in local:
                continue
            if table.catalog:
                errors.append(
                    ValidationError(
                        "QUALIFIED_REFERENCE_BLOCKED",
                        f"Three-part or remote references are not permitted: "
                        f"{table.sql(dialect=DIALECT)}.",
                    )
                )
                continue
            try:
                obj = self.store.authorize_object(database_name, schema or None, name, role)
            except Exception as exc:  # policy errors carry user-safe text
                errors.append(ValidationError(getattr(exc, "code", "ACCESS_DENIED"), str(exc)))
                continue
            resolved[obj.name.upper()] = obj
            if table.alias:
                resolved[table.alias.upper()] = obj

        if not resolved and not errors:
            errors.append(
                ValidationError(
                    "NO_APPROVED_OBJECT",
                    "The query does not reference any approved table or view.",
                )
            )
        return resolved

    # ---- 6. columns --------------------------------------------------------

    def _check_columns(
        self,
        tree: exp.Expression,
        objects: dict[str, ObjectPolicy],
        role: Role,
        errors: list[ValidationError],
        warnings: list[str],
    ) -> None:
        distinct_objects = {obj.fqn: obj for obj in objects.values()}
        clearance = role.clearance_rank

        for column in tree.find_all(exp.Column):
            col_name = column.name.upper()
            qualifier = (column.table or "").upper()

            candidates = (
                [objects[qualifier]]
                if qualifier and qualifier in objects
                else list(distinct_objects.values())
            )
            for obj in candidates:
                policy_col = obj.column(col_name)
                if policy_col is None:
                    if obj.columns_declared:
                        continue
                    # Object allowlisted without a column list. Classify by name so
                    # the clearance check still bites here rather than deferring
                    # entirely to output masking.
                    inferred = self.store.infer_column_sensitivity(col_name)
                    policy_col = ColumnPolicy(name=col_name, sensitivity=inferred)
                if policy_col.rank > clearance:
                    errors.append(
                        ValidationError(
                            "RESTRICTED_COLUMN",
                            f"Column {obj.fqn}.{policy_col.name} is classified "
                            f"{policy_col.sensitivity}; role '{role.name}' holds "
                            f"{role.clearance} clearance.",
                        )
                    )
                break
            else:
                if qualifier and qualifier not in objects:
                    warnings.append(
                        f"Column reference {column.sql(dialect=DIALECT)} uses an unrecognised "
                        "qualifier; it will be resolved by Oracle."
                    )

    def _expand_star(
        self,
        tree: exp.Expression,
        objects: dict[str, ObjectPolicy],
        role: Role,
        warnings: list[str],
        database_name: str,
    ) -> exp.Expression:
        """Replace ``SELECT *`` with the columns this role may actually see.

        Only done when a single object is in play, because that is the only case
        where attribution is unambiguous. Otherwise the star survives and the
        masking layer redacts over-classified columns on the way out.
        """
        # Must look for a star in a projection list specifically, not anywhere in
        # the tree: COUNT(*) contains a Star that is not a wildcard projection,
        # and treating it as one warns about an expansion that never happens.
        if not any(
            isinstance(e, exp.Star)
            for select in tree.find_all(exp.Select)
            for e in select.expressions
        ):
            return tree
        distinct = {obj.fqn: obj for obj in objects.values()}
        if len(distinct) != 1:
            warnings.append(
                "SELECT * across multiple objects was not expanded; restricted columns are "
                "masked in the result instead."
            )
            return tree

        obj = next(iter(distinct.values()))
        try:
            all_columns = self.store.columns_for(database_name, obj)
        except ChatbotError:
            # Discovery is unavailable; leave the star for masking to handle.
            return tree
        visible = tuple(c for c in all_columns if c.rank <= role.clearance_rank)
        if not visible:
            return tree
        hidden = len(all_columns) - len(visible)

        for select in tree.find_all(exp.Select):
            if any(isinstance(e, exp.Star) for e in select.expressions):
                select.set(
                    "expressions",
                    [exp.column(c.name) for c in visible],
                )
        if hidden:
            warnings.append(
                f"SELECT * was expanded to the {len(visible)} columns available to role "
                f"'{role.name}'; {hidden} restricted column(s) were excluded."
            )
        else:
            warnings.append(f"SELECT * was expanded to {len(visible)} named columns.")
        return tree

    # ---- 7. shape rules ----------------------------------------------------

    def _check_cartesian(
        self, tree: exp.Expression, role: Role, errors: list[ValidationError]
    ) -> None:
        if self.allow_cartesian or role.allow_cartesian:
            return
        for select in tree.find_all(exp.Select):
            for join in select.args.get("joins") or []:
                kind = (join.args.get("kind") or "").upper()
                has_predicate = bool(join.args.get("on") or join.args.get("using"))
                if kind == "CROSS" or not has_predicate:
                    target = join.this.sql(dialect=DIALECT) if join.this else "unknown"
                    errors.append(
                        ValidationError(
                            "CARTESIAN_JOIN",
                            f"The join to {target} has no join condition, which produces a "
                            "cartesian product. Add an ON clause.",
                        )
                    )

    def _is_aggregate(self, tree: exp.Expression) -> bool:
        for select in tree.find_all(exp.Select):
            if select.args.get("group"):
                return True
            if any(isinstance(e, exp.AggFunc) for e in select.find_all(exp.AggFunc)):
                return True
        return False

    def _check_required_filters(
        self,
        tree: exp.Expression,
        objects: dict[str, ObjectPolicy],
        is_aggregate: bool,
        errors: list[ValidationError],
    ) -> None:
        needs_filter = {obj.fqn: obj for obj in objects.values() if obj.require_filter}
        if not needs_filter or is_aggregate:
            return
        if tree.find(exp.Where) is not None:
            return
        names = ", ".join(sorted(needs_filter))
        errors.append(
            ValidationError(
                "MISSING_FILTER",
                f"{names} is a large transactional object and cannot be scanned without a "
                "WHERE clause. Add a filter (for example a date range or a customer "
                "identifier) or use an aggregate.",
            )
        )

    # ---- 8. rewrite --------------------------------------------------------

    def _apply_row_limit(
        self, tree: exp.Expression, limit: int, is_aggregate: bool
    ) -> tuple[exp.Expression, int, list[str]]:
        """Cap the result set. Applied to aggregates too, as a memory backstop."""
        notes: list[str] = []
        existing = tree.args.get("limit")
        current: int | None = None
        if existing is not None:
            count = existing.args.get("count") if isinstance(existing, exp.Fetch) else existing.expression
            try:
                current = int(count.name if hasattr(count, "name") else count)
            except (TypeError, ValueError):
                current = None

        if current is None:
            tree = tree.limit(limit)
            if not is_aggregate:
                notes.append(f"A row limit of {limit} was applied automatically.")
            return tree, limit, notes

        if current > limit:
            tree.set("limit", None)
            tree = tree.limit(limit)
            notes.append(
                f"The requested row limit of {current} exceeds the maximum of {limit} "
                f"and was reduced to {limit}."
            )
            return tree, limit, notes

        return tree, current, notes

    # ---- helpers -----------------------------------------------------------

    def _reject(self, errors: list[ValidationError]) -> ValidationResult:
        return ValidationResult(
            validation_status="REJECTED",
            validation_errors=errors,
            rewritten_safe_sql=None,
            sql_fingerprint=None,
            explanation=(
                "The statement was rejected before execution. "
                + " ".join(e.message for e in errors)
            ),
        )

    def _explain(
        self,
        objects: dict[str, ObjectPolicy],
        limit: int | None,
        is_aggregate: bool,
        warnings: list[str],
    ) -> str:
        names = ", ".join(sorted({obj.fqn for obj in objects.values()}))
        parts = [
            f"Read-only SELECT against approved object(s): {names}.",
            f"Result capped at {limit} rows.",
        ]
        if is_aggregate:
            parts.append("The query aggregates, so it summarises rather than lists records.")
        parts.extend(warnings)
        return " ".join(parts)
