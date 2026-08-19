"""Discovery-mode policy: undeclared columns and wildcard schemas.

Two deployment shapes are covered here.

*On-Prem* names its objects explicitly but declares no columns, so the object
allowlist still bites while the column list is read from the data dictionary.

*ATP* allowlists no objects at all and lets the database grant decide, which is
the weaker of the two. The tests below pin down what survives that trade: role
clearance, schema exclusions, and failing closed when the dictionary is down.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oracle_mcp.errors import AccessDeniedError, ObjectNotAllowlistedError
from oracle_mcp.masking import Masker
from oracle_mcp.policy import PolicyStore, clear_policy_cache
from oracle_mcp.sql_guard import SqlGuard

# This module is entirely about the access model, so every test here asserts a
# security control.
pytestmark = pytest.mark.security


class FakeDictionary:
    """Stands in for the ALL_* views. Only returns what it was told about."""

    def __init__(self, catalog: dict[str, dict[str, list[str]]]) -> None:
        self.catalog = catalog
        self.down = False
        self.calls: list[tuple[str, ...]] = []

    def list_schemas(self, database: str) -> tuple[str, ...]:
        self.calls.append(("schemas", database))
        if self.down:
            return ()
        return tuple(sorted(self.catalog.get(database, {})))

    def list_objects(self, database: str, schema: str) -> tuple[tuple[str, str], ...]:
        self.calls.append(("objects", database, schema))
        if self.down:
            return ()
        return tuple(
            (name, "TABLE") for name in sorted(self.catalog.get(database, {}).get(schema, {}))
        )

    def list_columns(self, database: str, schema: str, object_name: str) -> tuple[str, ...]:
        self.calls.append(("columns", database, schema, object_name))
        if self.down:
            return ()
        return tuple(self.catalog.get(database, {}).get(schema, {}).get(object_name, []))


ONPREM_CATALOG = {
    "ONPREM": {
        "EIM": {
            "EIM_PR_SYSTEM": ["SYSTEM_ID", "SERIAL_NUMBER", "CONTACT_EMAIL", "TAX_ID"],
            "EIM_PR_ROLES": ["ROLE_ID", "ROLE_NAME"],
            "EIM_PR_SECRETS": ["SECRET_ID", "API_KEY"],
        }
    }
}

ATP_CATALOG = {
    "ATP": {
        "SALES": {"ORDERS": ["ORDER_ID", "ORDER_DATE", "SALARY"]},
        "NAPP_READONLY": {"ACCOUNTS": ["ACCOUNT_ID", "ACCOUNT_NAME"]},
        "LEGACY_STAGING": {"STG_DUMP": ["ID"]},
        "SYS": {"USER$": ["NAME", "PASSWORD"]},
    }
}


def _store(policy_dir: Path, files: dict[str, str], catalog: dict) -> tuple[PolicyStore, FakeDictionary]:
    clear_policy_cache()
    store = PolicyStore(policy_dir, files)
    dictionary = FakeDictionary(catalog)
    masker = Masker(store.masking_config)
    store.bind_dictionary(dictionary, masker.infer_sensitivity)
    return store, dictionary


@pytest.fixture
def onprem_store(discovery_policy_dir: Path):
    return _store(discovery_policy_dir, {"ONPREM": "onprem_discover.yaml"}, ONPREM_CATALOG)


@pytest.fixture
def atp_store(discovery_policy_dir: Path):
    return _store(discovery_policy_dir, {"ATP": "atp_wildcard.yaml"}, ATP_CATALOG)


# ---- strict allowlist, discovered columns ----------------------------------


def test_undeclared_object_takes_its_columns_from_the_dictionary(onprem_store):
    store, _ = onprem_store
    obj = store.database("ONPREM").resolve_object("EIM", "EIM_PR_SYSTEM")
    assert obj.columns_declared is False

    names = [c.name for c in store.columns_for("ONPREM", obj)]
    assert names == ["SYSTEM_ID", "SERIAL_NUMBER", "CONTACT_EMAIL", "TAX_ID"]


def test_discovered_columns_are_classified_by_the_masking_rules(onprem_store):
    store, _ = onprem_store
    obj = store.database("ONPREM").resolve_object("EIM", "EIM_PR_SYSTEM")
    by_name = {c.name: c.sensitivity for c in store.columns_for("ONPREM", obj)}

    assert by_name["SYSTEM_ID"] == "INTERNAL"
    assert by_name["CONTACT_EMAIL"] == "CONFIDENTIAL"
    assert by_name["TAX_ID"] == "RESTRICTED"


def test_an_object_absent_from_the_allowlist_stays_unreachable(onprem_store):
    """The dictionary knows about EIM_PR_SECRETS; the allowlist does not."""
    store, _ = onprem_store
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ONPREM", "EIM", "EIM_PR_SECRETS", store.role("admin"))


def test_discovered_restricted_column_is_rejected_below_clearance(onprem_store):
    store, _ = onprem_store
    guard = SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)

    result = guard.validate(
        "SELECT tax_id FROM eim.eim_pr_system WHERE system_id = 1",
        database_name="ONPREM",
        role=store.role("business_user"),
    )
    assert result.approved is False
    assert any(e.code == "RESTRICTED_COLUMN" for e in result.validation_errors)


def test_the_same_column_is_allowed_at_sufficient_clearance(onprem_store):
    store, _ = onprem_store
    guard = SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)

    result = guard.validate(
        "SELECT tax_id FROM eim.eim_pr_system WHERE system_id = 1",
        database_name="ONPREM",
        role=store.role("admin"),
    )
    assert result.approved is True


def test_star_expands_to_the_columns_the_role_may_see(onprem_store):
    store, _ = onprem_store
    guard = SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)

    result = guard.validate(
        "SELECT * FROM eim.eim_pr_roles",
        database_name="ONPREM",
        role=store.role("business_user"),
    )
    assert result.approved is True
    assert "ROLE_NAME" in result.rewritten_safe_sql.upper()
    assert "*" not in result.rewritten_safe_sql


# ---- wildcard schemas ------------------------------------------------------


def test_wildcard_mode_reaches_a_schema_no_yaml_declares(atp_store):
    store, _ = atp_store
    obj = store.authorize_object("ATP", "SALES", "ORDERS", store.role("analyst"))
    assert obj.fqn == "SALES.ORDERS"


def test_wildcard_mode_lists_discovered_schemas_without_oracle_internals(atp_store):
    store, _ = atp_store
    names = [s.name for s in store.allowed_schemas("ATP", store.role("analyst"))]
    assert "SALES" in names
    assert "NAPP_READONLY" in names
    assert "SYS" not in names


def test_wildcard_mode_refuses_an_oracle_internal_schema(atp_store):
    store, _ = atp_store
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "SYS", "USER$", store.role("admin"))


def test_an_extra_excluded_schema_is_refused(atp_store):
    """excluded_schemas in the YAML adds to the built-in Oracle exclusions."""
    store, _ = atp_store
    assert "LEGACY_STAGING" not in [
        s.name for s in store.allowed_schemas("ATP", store.role("admin"))
    ]
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "LEGACY_STAGING", "STG_DUMP", store.role("admin"))


def test_an_object_the_account_cannot_read_is_refused(atp_store):
    """Wildcard mode delegates existence to the grant, so an ungranted object
    simply does not appear in the dictionary and is denied."""
    store, _ = atp_store
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "SALES", "NOT_GRANTED_TO_US", store.role("admin"))


def test_a_dictionary_outage_fails_closed(atp_store):
    store, dictionary = atp_store
    dictionary.down = True
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "SALES", "ORDERS", store.role("admin"))


def test_wildcard_does_not_bypass_column_clearance(atp_store):
    store, _ = atp_store
    guard = SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)

    result = guard.validate(
        "SELECT salary FROM sales.orders",
        database_name="ATP",
        role=store.role("business_user"),
    )
    assert result.approved is False
    assert any(e.code == "RESTRICTED_COLUMN" for e in result.validation_errors)


def test_a_role_without_the_wildcard_cannot_use_it(discovery_policy_dir: Path):
    """The wildcard lives in roles.yaml, so a role scoped to named schemas keeps
    its scope even on a wildcard database."""
    store, _ = _store(discovery_policy_dir, {"ATP": "atp_wildcard.yaml"}, ATP_CATALOG)
    scoped = store.role("analyst").__class__(
        name="scoped", clearance="CONFIDENTIAL", schemas={"ATP": ("NAPP_READONLY",)}
    )
    store.authorize_object("ATP", "NAPP_READONLY", "ACCOUNTS", scoped)
    with pytest.raises(AccessDeniedError):
        store.authorize_object("ATP", "SALES", "ORDERS", scoped)


# ---- the deployed configuration -------------------------------------------


def test_deployed_onprem_exposes_exactly_the_five_agreed_objects(deployed_policy_dir: Path):
    clear_policy_cache()
    store = PolicyStore(deployed_policy_dir, {"ONPREM": "onprem.yaml"})
    policy = store.database("ONPREM")

    assert policy.allow_all_schemas is False
    assert sorted(o.fqn for o in policy.iter_objects()) == [
        "EIM.EIM_DRM_PRODUCT_DETAILS",
        "EIM.EIM_PR_IB_LATEST",
        "EIM.EIM_PR_ROLES",
        "EIM.EIM_PR_SN_SO_REF_PUB",
        "EIM.EIM_PR_SYSTEM",
    ]


def test_deployed_atp_is_wildcard_and_every_role_can_use_it(deployed_policy_dir: Path):
    clear_policy_cache()
    store = PolicyStore(deployed_policy_dir, {"ATP": "atp.yaml"})

    assert store.database("ATP").allow_all_schemas is True
    for name in store.roles:
        assert store.role(name).has_wildcard_schemas("ATP"), name
