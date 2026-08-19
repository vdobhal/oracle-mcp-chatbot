"""Allowlist and role-based access control.

Three independent layers must all say yes before a byte of data moves:

1. Database grants  - the read-only user physically cannot see anything else.
2. This allowlist   - only objects declared in ``config/policy/<db>.yaml``.
3. Role clearance   - the caller's role must reach the object/column
                      classification, and must list the schema.

Layer 3 is the only one an attacker could influence through tool arguments, so
``role_binding_mode=env`` pins the role outside the model's reach.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

import yaml

from .errors import (
    AccessDeniedError,
    ConfigurationError,
    ObjectNotAllowlistedError,
    UnknownRoleError,
)

# Higher number == more sensitive. "NEVER" is above every real clearance, so a
# column marked NEVER is unreachable by any role including admin.
SENSITIVITY_ORDER: dict[str, int] = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
    "NEVER": 99,
}


def sensitivity_rank(level: str | None) -> int:
    if not level:
        return SENSITIVITY_ORDER["INTERNAL"]
    rank = SENSITIVITY_ORDER.get(level.strip().upper())
    if rank is None:
        raise ConfigurationError(f"Unknown sensitivity level: {level!r}")
    return rank


@dataclass(frozen=True)
class ColumnPolicy:
    name: str
    description: str = ""
    sensitivity: str = "INTERNAL"

    @property
    def rank(self) -> int:
        return sensitivity_rank(self.sensitivity)


@dataclass(frozen=True)
class ObjectPolicy:
    schema: str
    name: str
    object_type: str = "TABLE"
    description: str = ""
    business_domain: str = ""
    sensitivity: str = "INTERNAL"
    large_table: bool = False
    require_filter: bool = False
    columns: tuple[ColumnPolicy, ...] = ()

    @property
    def fqn(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def rank(self) -> int:
        return sensitivity_rank(self.sensitivity)

    @property
    def columns_declared(self) -> bool:
        """False when the policy file allowlists the object but not its columns.

        Such an object takes its column list from the data dictionary at query
        time. Use ``PolicyStore.columns_for`` rather than ``.columns`` anywhere
        the full list matters, otherwise these objects look like they have none.
        """
        return bool(self.columns)

    def column(self, name: str) -> ColumnPolicy | None:
        target = name.strip().upper()
        for col in self.columns:
            if col.name.upper() == target:
                return col
        return None

    def columns_visible_to(self, clearance: int) -> tuple[ColumnPolicy, ...]:
        return tuple(c for c in self.columns if c.rank <= clearance)


@dataclass(frozen=True)
class SchemaPolicy:
    name: str
    description: str = ""
    business_domain: str = ""
    objects: tuple[ObjectPolicy, ...] = ()

    def object(self, name: str) -> ObjectPolicy | None:
        target = name.strip().upper()
        for obj in self.objects:
            if obj.name.upper() == target:
                return obj
        return None


@dataclass(frozen=True)
class Role:
    name: str
    description: str = ""
    clearance: str = "INTERNAL"
    max_rows: int = 200
    allow_raw_sql: bool = False
    show_sql: bool = False
    allow_cartesian: bool = False
    allow_reconciliation: bool = False
    schemas: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def clearance_rank(self) -> int:
        return sensitivity_rank(self.clearance)

    def schemas_for(self, database: str) -> tuple[str, ...]:
        return self.schemas.get(database.upper(), ())

    def has_wildcard_schemas(self, database: str) -> bool:
        return "*" in self.schemas_for(database)

    def can_see_schema(self, database: str, schema: str) -> bool:
        allowed = self.schemas_for(database)
        if "*" in allowed:
            return True
        return schema.strip().upper() in {s.upper() for s in allowed}


# Oracle ships these; none of them hold business data, and several are a direct
# route to credential hashes or audit tampering. Excluded from wildcard discovery
# regardless of what the connected account happens to have been granted.
ORACLE_INTERNAL_SCHEMAS: frozenset[str] = frozenset(
    {
        "SYS", "SYSTEM", "SYSAUX", "AUDSYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC",
        "OUTLN", "DBSNMP", "APPQOSSYS", "GSMADMIN_INTERNAL", "GSMCATUSER", "GSMUSER",
        "XDB", "WMSYS", "CTXSYS", "MDSYS", "ORDSYS", "ORDDATA", "ORDPLUGINS", "SI_INFORMTN_SCHEMA",
        "OLAPSYS", "OJVMSYS", "DVSYS", "DVF", "LBACSYS", "DBSFWUSER", "REMOTE_SCHEDULER_AGENT",
        "ANONYMOUS", "XS$NULL", "SPATIAL_CSW_ADMIN_USR", "SPATIAL_WFS_ADMIN_USR",
        "FLOWS_FILES", "APEX_PUBLIC_USER", "ORACLE_OCM", "PDBADMIN", "GGSYS",
        "DBSNMP_ADMIN", "C##CLOUD$SERVICE", "ADB_MONITOR", "DGPDB_INT",
    }
)


@dataclass(frozen=True)
class DatabasePolicy:
    database: str
    display_name: str
    description: str
    default_schema: str
    schemas: tuple[SchemaPolicy, ...]
    allow_all_schemas: bool = False
    excluded_schemas: frozenset[str] = ORACLE_INTERNAL_SCHEMAS

    def schema(self, name: str) -> SchemaPolicy | None:
        target = name.strip().upper()
        for sch in self.schemas:
            if sch.name.upper() == target:
                return sch
        return None

    def is_excluded_schema(self, name: str) -> bool:
        upper = (name or "").strip().upper()
        # C## prefixes are common-user containers in a CDB; never business data.
        return upper in self.excluded_schemas or upper.startswith("C##")

    def resolve_object(self, schema: str | None, name: str) -> ObjectPolicy | None:
        sch = self.schema(schema or self.default_schema)
        return sch.object(name) if sch else None

    def iter_objects(self) -> Iterable[ObjectPolicy]:
        for sch in self.schemas:
            yield from sch.objects


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigurationError(f"Policy file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ConfigurationError(f"Policy file is not a YAML mapping: {path}")
    return data


def load_database_policy(path: Path) -> DatabasePolicy:
    raw = _load_yaml(path)
    schemas: list[SchemaPolicy] = []
    for sch in raw.get("schemas") or []:
        objects: list[ObjectPolicy] = []
        for obj in sch.get("objects") or []:
            columns = tuple(
                ColumnPolicy(
                    name=str(c["name"]).upper(),
                    description=str(c.get("description", "")),
                    sensitivity=str(c.get("sensitivity", "INTERNAL")).upper(),
                )
                for c in (obj.get("columns") or [])
            )
            objects.append(
                ObjectPolicy(
                    schema=str(sch["name"]).upper(),
                    name=str(obj["name"]).upper(),
                    object_type=str(obj.get("type", "TABLE")).upper(),
                    description=str(obj.get("description", "")),
                    business_domain=str(obj.get("business_domain", sch.get("business_domain", ""))),
                    sensitivity=str(obj.get("sensitivity", "INTERNAL")).upper(),
                    large_table=bool(obj.get("large_table", False)),
                    require_filter=bool(obj.get("require_filter", False)),
                    columns=columns,
                )
            )
        schemas.append(
            SchemaPolicy(
                name=str(sch["name"]).upper(),
                description=str(sch.get("description", "")),
                business_domain=str(sch.get("business_domain", "")),
                objects=tuple(objects),
            )
        )
    excluded = raw.get("excluded_schemas")
    return DatabasePolicy(
        database=str(raw.get("database", "")).upper(),
        display_name=str(raw.get("display_name", raw.get("database", ""))),
        description=str(raw.get("description", "")),
        default_schema=str(raw.get("default_schema", "")).upper(),
        schemas=tuple(schemas),
        allow_all_schemas=bool(raw.get("allow_all_schemas", False)),
        excluded_schemas=(
            ORACLE_INTERNAL_SCHEMAS | {str(s).upper() for s in excluded}
            if excluded
            else ORACLE_INTERNAL_SCHEMAS
        ),
    )


def load_roles(path: Path) -> tuple[dict[str, Role], str]:
    raw = _load_yaml(path)
    roles: dict[str, Role] = {}
    for name, cfg in (raw.get("roles") or {}).items():
        roles[name.lower()] = Role(
            name=name.lower(),
            description=str(cfg.get("description", "")).strip(),
            clearance=str(cfg.get("clearance", "INTERNAL")).upper(),
            max_rows=int(cfg.get("max_rows", 200)),
            allow_raw_sql=bool(cfg.get("allow_raw_sql", False)),
            show_sql=bool(cfg.get("show_sql", False)),
            allow_cartesian=bool(cfg.get("allow_cartesian", False)),
            allow_reconciliation=bool(cfg.get("allow_reconciliation", False)),
            schemas={
                str(db).upper(): tuple(str(s).upper() for s in schemas)
                for db, schemas in (cfg.get("schemas") or {}).items()
            },
        )
    if not roles:
        raise ConfigurationError("roles.yaml defines no roles")
    default_role = str(raw.get("default_role", "")).lower()
    if default_role not in roles:
        raise ConfigurationError(f"default_role {default_role!r} is not a defined role")
    return roles, default_role


class DictionaryResolver(Protocol):
    """Live data-dictionary lookups, supplied by the metadata service.

    Kept as a protocol rather than an import so this module stays free of any
    database dependency; the wiring happens in the service layer.
    """

    def list_schemas(self, database: str) -> tuple[str, ...]:
        ...

    def list_objects(self, database: str, schema: str) -> tuple[tuple[str, str], ...]:
        """Return ``(object_name, object_type)`` pairs the account can read."""

    def list_columns(self, database: str, schema: str, object_name: str) -> tuple[str, ...]:
        ...


class PolicyStore:
    """Loaded policy for every database this process serves, plus the role model."""

    def __init__(self, policy_dir: Path, policy_files: dict[str, str]) -> None:
        self.policy_dir = Path(policy_dir)
        self.roles, self.default_role_name = load_roles(self.policy_dir / "roles.yaml")
        self.masking_config = _load_yaml(self.policy_dir / "masking.yaml")
        self.databases: dict[str, DatabasePolicy] = {}
        for database_name, filename in policy_files.items():
            policy = load_database_policy(self.policy_dir / filename)
            self.databases[database_name.upper()] = policy
        self._resolver: DictionaryResolver | None = None
        self._infer_sensitivity: Callable[[str], str] = lambda _name: "INTERNAL"

    def bind_dictionary(
        self,
        resolver: DictionaryResolver,
        sensitivity_inferrer: Callable[[str], str] | None = None,
    ) -> None:
        """Attach live discovery, used by wildcard schemas and undeclared columns.

        ``sensitivity_inferrer`` classifies a discovered column by name. It is
        injected rather than imported because the masking module depends on this
        one. Leaving it unset means every discovered column lands at INTERNAL,
        which would quietly disable the clearance check on those columns.
        """
        self._resolver = resolver
        if sensitivity_inferrer is not None:
            self._infer_sensitivity = sensitivity_inferrer

    @property
    def has_dictionary(self) -> bool:
        return self._resolver is not None

    def infer_column_sensitivity(self, column_name: str) -> str:
        return self._infer_sensitivity(column_name.upper())

    def _require_resolver(self, policy: DatabasePolicy) -> DictionaryResolver:
        if self._resolver is None:
            raise ConfigurationError(
                f"{policy.display_name} relies on live data-dictionary discovery, "
                "but no dictionary resolver is bound to the policy store."
            )
        return self._resolver

    # ---- discovery ---------------------------------------------------------

    def columns_for(self, database_name: str, obj: ObjectPolicy) -> tuple[ColumnPolicy, ...]:
        """The object's columns, declared in policy or discovered in the database."""
        if obj.columns_declared:
            return obj.columns
        policy = self.database(database_name)
        resolver = self._require_resolver(policy)
        names = resolver.list_columns(policy.database, obj.schema, obj.name)
        return tuple(
            ColumnPolicy(
                name=name.upper(),
                description="",
                sensitivity=self._infer_sensitivity(name.upper()),
            )
            for name in names
        )

    # ---- lookups -----------------------------------------------------------

    def database(self, database_name: str) -> DatabasePolicy:
        policy = self.databases.get((database_name or "").strip().upper())
        if policy is None:
            known = ", ".join(sorted(self.databases)) or "none"
            raise ObjectNotAllowlistedError(
                f"Database {database_name!r} is not served by this MCP server. "
                f"Available: {known}.",
                next_steps=[f"Retry with one of: {known}"],
            )
        return policy

    def role(self, role_name: str | None) -> Role:
        key = (role_name or self.default_role_name).strip().lower()
        role = self.roles.get(key)
        if role is None:
            raise UnknownRoleError(
                f"Role {role_name!r} is not defined.",
                next_steps=[f"Use one of: {', '.join(sorted(self.roles))}"],
            )
        return role

    # ---- authorisation -----------------------------------------------------

    def authorize_object(
        self, database_name: str, schema: str | None, object_name: str, role: Role
    ) -> ObjectPolicy:
        """Return the object policy, or raise if the role may not touch it.

        The two failure modes are deliberately worded the same way. Telling a
        caller "that object exists but you lack clearance" is itself a schema
        disclosure, so both paths say only that it is not available.
        """
        policy = self.database(database_name)
        schema_name = (schema or policy.default_schema).strip().upper()
        obj = policy.resolve_object(schema_name, object_name)
        if obj is None and policy.allow_all_schemas:
            obj = self._discover_object(policy, schema_name, object_name)
        if obj is None:
            raise ObjectNotAllowlistedError(
                f"{schema_name}.{object_name.upper()} is not an approved object on "
                f"{policy.display_name}.",
                next_steps=[
                    "Call list_allowed_tables to see approved objects for this schema.",
                    "Ask a data steward to add the object to the allowlist if it is needed.",
                ],
            )
        if not role.can_see_schema(policy.database, obj.schema):
            raise AccessDeniedError(
                f"Schema {obj.schema} is not available to role '{role.name}'.",
                next_steps=["Call list_allowed_schemas to see what your role can access."],
            )
        if obj.rank > role.clearance_rank:
            raise AccessDeniedError(
                f"{obj.fqn} is classified {obj.sensitivity} and role '{role.name}' "
                f"holds {role.clearance} clearance.",
                next_steps=[
                    "Request a curated reporting view for this data.",
                    "Ask data governance to review your role clearance.",
                ],
            )
        return obj

    def _discover_object(
        self, policy: DatabasePolicy, schema_name: str, object_name: str
    ) -> ObjectPolicy | None:
        """Build an object policy for a database running in wildcard mode.

        Existence is decided by the data dictionary as seen through the chatbot's
        own account, so an object the account was never granted simply is not
        found. That makes the database grant the effective allowlist, which is why
        wildcard mode is only defensible against a genuinely read-only account.
        """
        if policy.is_excluded_schema(schema_name):
            return None
        resolver = self._require_resolver(policy)
        target = object_name.strip().upper()
        for name, object_type in resolver.list_objects(policy.database, schema_name):
            if name.upper() == target:
                return ObjectPolicy(
                    schema=schema_name,
                    name=target,
                    object_type=object_type.upper() or "TABLE",
                    description="Discovered from the data dictionary.",
                    business_domain=schema_name,
                    sensitivity="INTERNAL",
                    require_filter=False,
                    columns=(),
                )
        return None

    def columns_visible_to(
        self, database_name: str, obj: ObjectPolicy, clearance_rank: int
    ) -> tuple[ColumnPolicy, ...]:
        return tuple(
            c for c in self.columns_for(database_name, obj) if c.rank <= clearance_rank
        )

    def authorize_column(self, obj: ObjectPolicy, column_name: str, role: Role) -> ColumnPolicy:
        col = obj.column(column_name)
        if col is None:
            raise ObjectNotAllowlistedError(
                f"Column {column_name.upper()} is not an approved column on {obj.fqn}.",
                next_steps=["Call get_table_metadata to see approved columns."],
            )
        if col.rank > role.clearance_rank:
            raise AccessDeniedError(
                f"Column {obj.fqn}.{col.name} is classified {col.sensitivity} and role "
                f"'{role.name}' holds {role.clearance} clearance.",
                next_steps=[
                    "Re-ask the question without the restricted column.",
                    "Aggregate counts over the column instead of listing values.",
                ],
            )
        return col

    def allowed_schemas(self, database_name: str, role: Role) -> list[SchemaPolicy]:
        policy = self.database(database_name)
        declared = {s.name.upper(): s for s in policy.schemas}
        if policy.allow_all_schemas:
            resolver = self._require_resolver(policy)
            for name in resolver.list_schemas(policy.database):
                upper = name.upper()
                if policy.is_excluded_schema(upper) or upper in declared:
                    continue
                declared[upper] = SchemaPolicy(
                    name=upper,
                    description="Discovered from the data dictionary.",
                    business_domain=upper,
                    objects=(),
                )
        return [
            declared[name]
            for name in sorted(declared)
            if role.can_see_schema(policy.database, name)
        ]

    def allowed_objects(
        self, database_name: str, role: Role, schema: str | None = None
    ) -> list[ObjectPolicy]:
        policy = self.database(database_name)
        wanted = schema.strip().upper() if schema else None
        objects = {
            obj.fqn: obj
            for obj in policy.iter_objects()
            if wanted is None or obj.schema == wanted
        }
        if policy.allow_all_schemas:
            # Enumerating every object in every schema would be an unbounded
            # dictionary scan, so wildcard listing is scoped to one schema.
            targets = (
                [wanted]
                if wanted
                else [s.name for s in self.allowed_schemas(database_name, role)]
            )
            resolver = self._require_resolver(policy)
            for schema_name in targets:
                if policy.is_excluded_schema(schema_name):
                    continue
                for name, object_type in resolver.list_objects(policy.database, schema_name):
                    fqn = f"{schema_name}.{name.upper()}"
                    if fqn in objects:
                        continue
                    objects[fqn] = ObjectPolicy(
                        schema=schema_name,
                        name=name.upper(),
                        object_type=object_type.upper() or "TABLE",
                        description="Discovered from the data dictionary.",
                        business_domain=schema_name,
                    )
        return [
            objects[fqn]
            for fqn in sorted(objects)
            if role.can_see_schema(policy.database, objects[fqn].schema)
            and objects[fqn].rank <= role.clearance_rank
        ]

    def effective_max_rows(self, role: Role, server_max_rows: int) -> int:
        """The tighter of the role cap and the server cap. Never the looser one."""
        return max(1, min(role.max_rows, server_max_rows))


@functools.lru_cache(maxsize=4)
def _cached_store(policy_dir: str, policy_files_key: tuple[tuple[str, str], ...]) -> PolicyStore:
    return PolicyStore(Path(policy_dir), dict(policy_files_key))


def get_policy_store(policy_dir: Path, policy_files: dict[str, str]) -> PolicyStore:
    return _cached_store(str(policy_dir), tuple(sorted(policy_files.items())))


def clear_policy_cache() -> None:
    _cached_store.cache_clear()
