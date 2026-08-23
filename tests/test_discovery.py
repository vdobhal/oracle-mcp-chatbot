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
        # Readable by the account but outside discovered_schemas in the scoped
        # fixture, which is how the deployed ATP policy is configured.
        "APEX_240200": {"WWV_FLOW_APP": ["APP_ID"]},
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


@pytest.fixture
def atp_scoped_store(discovery_policy_dir: Path):
    return _store(discovery_policy_dir, {"ATP": "atp_scoped.yaml"}, ATP_CATALOG)


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


# ---- scoped discovery: named schemas, discovered objects -------------------


def test_scoped_discovery_reaches_objects_in_a_named_schema(atp_scoped_store):
    store, _ = atp_scoped_store
    obj = store.authorize_object("ATP", "SALES", "ORDERS", store.role("analyst"))
    assert obj.fqn == "SALES.ORDERS"
    assert [c.name for c in store.columns_for("ATP", obj)] == [
        "ORDER_ID",
        "ORDER_DATE",
        "SALARY",
    ]


def test_scoped_discovery_refuses_a_readable_schema_that_is_not_named(atp_scoped_store):
    """The whole point of the tier: the account can read APEX_240200, but the
    policy does not name it, so it stays unreachable."""
    store, _ = atp_scoped_store
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "APEX_240200", "WWV_FLOW_APP", store.role("admin"))


def test_scoped_discovery_lists_only_the_named_schemas(atp_scoped_store):
    store, _ = atp_scoped_store
    names = [s.name for s in store.allowed_schemas("ATP", store.role("admin"))]
    assert names == ["NAPP_READONLY", "SALES"]


def test_scoped_discovery_needs_no_dictionary_scan_to_list_schemas(atp_scoped_store):
    """A named list is known up front, so listing must not hit ALL_OBJECTS."""
    store, dictionary = atp_scoped_store
    store.allowed_schemas("ATP", store.role("admin"))
    assert not [c for c in dictionary.calls if c[0] == "schemas"]


def test_scoped_discovery_still_enforces_column_clearance(atp_scoped_store):
    store, _ = atp_scoped_store
    guard = SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)
    result = guard.validate(
        "SELECT salary FROM sales.orders",
        database_name="ATP",
        role=store.role("business_user"),
    )
    assert result.approved is False
    assert any(e.code == "RESTRICTED_COLUMN" for e in result.validation_errors)


def test_naming_schemas_overrides_the_wildcard(discovery_policy_dir: Path):
    """discovered_schemas must win even if allow_all_schemas is left true, so a
    narrowing edit cannot be silently undone by a stale flag."""
    clear_policy_cache()
    store = PolicyStore(discovery_policy_dir, {"ATP": "atp_scoped.yaml"})
    policy = store.database("ATP")
    object.__setattr__(policy, "allow_all_schemas", True)
    assert policy.is_discoverable("SALES") is True
    assert policy.is_discoverable("APEX_240200") is False


# ---- the deployed configuration -------------------------------------------


def test_deployed_onprem_exposes_exactly_the_governed_objects(deployed_policy_dir: Path):
    clear_policy_cache()
    store = PolicyStore(deployed_policy_dir, {"ONPREM": "onprem.yaml"})
    policy = store.database("ONPREM")

    assert policy.allow_all_schemas is False
    assert sorted(o.fqn for o in policy.iter_objects()) == [
        "EIM.EIM_DQ_RULES_LOOKUP",
        "EIM.EIM_DRM_PRODUCT_DETAILS",
        "EIM.EIM_PR_IB_LATEST",
        "EIM.EIM_PR_ROLES",
        "EIM.EIM_PR_SN_SO_REF_PUB",
        "EIM.EIM_PR_SYSTEM",
    ]


def test_deployed_atp_is_scoped_to_the_erp_schemas(deployed_policy_dir: Path):
    clear_policy_cache()
    store = PolicyStore(deployed_policy_dir, {"ATP": "atp.yaml"})
    policy = store.database("ATP")

    assert policy.discovered_schemas == {"NAPPERP", "NAPPERPADM", "NAPPERPDS"}
    assert policy.allow_all_schemas is False
    for erp in ("NAPPERP", "NAPPERPADM", "NAPPERPDS"):
        assert policy.is_discoverable(erp) is True, erp

    # Everything else NAPP_READONLY can read must stay out of reach.
    for other in ("APEX_240200", "RMAN$CATALOG", "GGADMIN", "SH", "ADMIN", "NAPPLIC"):
        assert policy.is_discoverable(other) is False, other


# ---- object exclusions and domain tagging ---------------------------------


@pytest.fixture
def deployed_atp(deployed_policy_dir: Path):
    """The real ATP policy over a fake dictionary of real NAPPERP object names."""
    catalog = {
        "ATP": {
            "NAPPERP": {
                "NAPP_IB_ASSETS_FROM_SAP_LOOPBACK_STG": ["ASSET_ID"],
                "NAPP_IB_ASSETS_FROM_SAP_LOOPBACK_STG_BK1217": ["ASSET_ID"],
                "NAPP_IB_EIM_SYNC_JOBS": ["JOB_ID"],
                "NAPP_IBP_SAFETYSTOCKS": ["ITEM_ID"],
                "NAPP_SM_EIM_SC_HDR_STG": ["CONTRACT_ID"],
                "NAPP_SC_TO_EIM_CONTRACT_STG_TBL": ["CONTRACT_ID"],
                "NAPP_PD_EIM_PDH_DETAILS_STG": ["ITEM_ID"],
                "NAPP_PLM_ITEM_DETAILS": ["ITEM_ID"],
                "NAPP_PLM_CO_ITEM_STG": ["ITEM_ID"],
                "NAPP_PLM_CO_ITEM_STG_ARCHIVE": ["ITEM_ID"],
                "NAPP_PLM_CO_ITEM_STG_BKP1": ["ITEM_ID"],
                "NAPP_PLM_PARTS_DATA_DETAILS_STG_29NOV2025": ["PART_ID"],
                "NAPP_PLM_PARTS_DATA_DETAILS_STG_29NOV25": ["PART_ID"],
                "NAPP_CDM_TO_ATP_SYNC": ["CUSTOMER_ID"],
                "NAPP_Q2C_ZUORA_SMP_CUSTOMER": ["CUSTOMER_ID"],
                "NAPP_ITC_CUSTOM_INVOICES_HEADER_STG": ["INVOICE_ID"],
                "GTM_CDM_MISMATCH_DUMP_22MAY": ["ROW_ID"],
                "GTM_CDM_MISMATCH_DUMP_18DEC": ["ROW_ID"],
                "TEMP_ASUP_FULL_LIST": ["ID"],
                "TMP_INSUFFICIENT_ORDERS": ["ID"],
                "TOAD_PLAN_TABLE": ["ID"],
                "NAPP_SNC_EVENTS_LOG": ["EVENT_ID"],
            }
        }
    }
    return _store(deployed_policy_dir, {"ATP": "atp.yaml"}, catalog)


EXCLUDED = [
    "GTM_CDM_MISMATCH_DUMP_22MAY",
    "GTM_CDM_MISMATCH_DUMP_18DEC",
    "NAPP_IB_ASSETS_FROM_SAP_LOOPBACK_STG_BK1217",
    "NAPP_PLM_CO_ITEM_STG_BKP1",
    "NAPP_PLM_PARTS_DATA_DETAILS_STG_29NOV2025",
    "NAPP_PLM_PARTS_DATA_DETAILS_STG_29NOV25",
    "TEMP_ASUP_FULL_LIST",
    "TMP_INSUFFICIENT_ORDERS",
    "TOAD_PLAN_TABLE",
]


@pytest.mark.parametrize("name", EXCLUDED)
def test_excluded_objects_are_hidden_from_listing(deployed_atp, name: str):
    store, _ = deployed_atp
    role = store.role("analyst")
    listed = {o.name for o in store.allowed_objects("ATP", role, "NAPPERP")}
    assert name not in listed


@pytest.mark.parametrize("name", EXCLUDED)
def test_excluded_objects_are_refused_when_named_directly(deployed_atp, name: str):
    """The control that matters: hiding from listing alone is decoration.

    A caller who already knows the name - or a model that guessed it from a
    sibling - must not be able to query it anyway.
    """
    store, _ = deployed_atp
    role = store.role("analyst")
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "NAPPERP", name, role)


def test_excluding_a_backup_keeps_its_live_counterpart(deployed_atp):
    """_ARCHIVE is deliberately not excluded; only _BKP and dated copies are."""
    store, _ = deployed_atp
    role = store.role("analyst")
    listed = {o.name for o in store.allowed_objects("ATP", role, "NAPPERP")}

    assert "NAPP_PLM_CO_ITEM_STG" in listed
    assert "NAPP_PLM_CO_ITEM_STG_ARCHIVE" in listed
    assert "NAPP_PLM_CO_ITEM_STG_BKP1" not in listed


@pytest.mark.parametrize(
    ("obj", "domain"),
    [
        ("NAPP_IB_ASSETS_FROM_SAP_LOOPBACK_STG", "Install Base"),
        ("NAPP_SM_EIM_SC_HDR_STG", "Service Contract"),
        ("NAPP_SC_TO_EIM_CONTRACT_STG_TBL", "Service Contract"),
        ("NAPP_PD_EIM_PDH_DETAILS_STG", "Product"),
        ("NAPP_PLM_ITEM_DETAILS", "Product"),
        ("NAPP_CDM_TO_ATP_SYNC", "Customer"),
        ("NAPP_Q2C_ZUORA_SMP_CUSTOMER", "Customer"),
    ],
)
def test_discovered_objects_carry_a_business_domain(deployed_atp, obj: str, domain: str):
    store, _ = deployed_atp
    role = store.role("analyst")
    assert store.authorize_object("ATP", "NAPPERP", obj, role).business_domain == domain


def test_ibp_is_not_mistaken_for_install_base(deployed_atp):
    """NAPP_IBP_ is Integrated Business Planning, not install base.

    The unanchored NAPP_IB* the domain map started from pulled in 23 supply
    chain objects. This is the regression guard for that anchoring.
    """
    store, _ = deployed_atp
    role = store.role("analyst")
    obj = store.authorize_object("ATP", "NAPPERP", "NAPP_IBP_SAFETYSTOCKS", role)
    assert obj.business_domain != "Install Base"


def test_eim_does_not_steal_objects_from_the_business_domains(deployed_atp):
    """EIM is an integration boundary that overlaps a third of the other groups.

    It is ordered last so an object that is both EIM and install base is
    labelled with the domain a user would actually ask about.
    """
    store, _ = deployed_atp
    role = store.role("analyst")
    for obj, domain in [
        ("NAPP_IB_EIM_SYNC_JOBS", "Install Base"),
        ("NAPP_SM_EIM_SC_HDR_STG", "Service Contract"),
        ("NAPP_PD_EIM_PDH_DETAILS_STG", "Product"),
    ]:
        assert store.authorize_object("ATP", "NAPPERP", obj, role).business_domain == domain


def test_custom_invoices_are_not_labelled_customer(deployed_atp):
    """NAPP_ITC_CUSTOM_INVOICES_ contains CUSTOM, not CUSTOMER."""
    store, _ = deployed_atp
    role = store.role("analyst")
    obj = store.authorize_object(
        "ATP", "NAPPERP", "NAPP_ITC_CUSTOM_INVOICES_HEADER_STG", role
    )
    assert obj.business_domain != "Customer"


def test_unmatched_objects_fall_back_to_the_schema_name(deployed_atp):
    store, _ = deployed_atp
    role = store.role("analyst")
    obj = store.authorize_object("ATP", "NAPPERP", "NAPP_SNC_EVENTS_LOG", role)
    assert obj.business_domain == "NAPPERP"


@pytest.fixture
def deployed_atp_ds(deployed_policy_dir: Path):
    """The real ATP policy over the customer-bearing objects in NAPPERPDS."""
    catalog = {
        "ATP": {
            "NAPPERPDS": {
                "HZ_PARTIES": ["PARTY_ID", "PARTY_NAME"],
                "HZ_CUST_ACCOUNTS": ["CUST_ACCOUNT_ID"],
                "NAPP_CX_PARTYEXTRACTPVO": ["PARTY_ID"],
                "NAPP_CX_CUSTOMERACCOUNTEXTRACTPVO": ["ACCOUNT_ID"],
                "NAPP_CX_CDMWORKBENCH_C": ["ID"],
                "NAPP_CX_CSE_ASSETS_B": ["ASSET_ID"],
                "NAPP_CX_OSS_SUBSCRIPTIONS": ["SUBSCRIPTION_ID"],
                "NAPP_CX_OSS_PRODUCTS": ["PRODUCT_ID"],
                "NAPP_CX_CONTRACTHEADEREXTRACTPVO": ["CONTRACT_ID"],
                "NAPP_CX_CONTRACTPARTYEXTRACTPVO": ["PARTY_ID"],
                "NAPP_CX_OKC_K_LINES_B": ["LINE_ID"],
                "NAPP_FSCM_CUSTPROFILEEXTRACTPVO": ["PROFILE_ID"],
                "RUPD$_NAPP_CX_LOCATIONEXTRACTPVO": ["LOCATION_ID"],
                "RUPD$_NAPP_CX_PARTYSITEEXTRACTPVO": ["SITE_ID"],
            }
        }
    }
    return _store(deployed_policy_dir, {"ATP": "atp.yaml"}, catalog)


@pytest.mark.parametrize(
    ("obj", "domain"),
    [
        # Oracle TCA views: the canonical Fusion customer model.
        ("HZ_PARTIES", "Customer"),
        ("HZ_CUST_ACCOUNTS", "Customer"),
        # BI extract snapshots of the same data.
        ("NAPP_CX_PARTYEXTRACTPVO", "Customer"),
        ("NAPP_CX_CUSTOMERACCOUNTEXTRACTPVO", "Customer"),
        ("NAPP_FSCM_CUSTPROFILEEXTRACTPVO", "Customer"),
    ],
)
def test_napperpds_customer_objects_route_to_customer(deployed_atp_ds, obj, domain):
    store, _ = deployed_atp_ds
    role = store.role("analyst")
    got = store.authorize_object("ATP", "NAPPERPDS", obj, role)
    assert got.business_domain == domain


@pytest.mark.parametrize(
    ("obj", "domain"),
    [
        ("NAPP_CX_CSE_ASSETS_B", "Install Base"),
        ("NAPP_CX_OSS_SUBSCRIPTIONS", "Product"),
        ("NAPP_CX_OSS_PRODUCTS", "Product"),
        ("NAPP_CX_CONTRACTHEADEREXTRACTPVO", "Service Contract"),
        ("NAPP_CX_CONTRACTPARTYEXTRACTPVO", "Service Contract"),
        ("NAPP_CX_OKC_K_LINES_B", "Service Contract"),
    ],
)
def test_cx_prefix_alone_does_not_make_an_object_customer(deployed_atp_ds, obj, domain):
    """NAPP_CX_ is the Fusion CX pillar, not the customer domain.

    Its 42 objects span assets, subscriptions and contracts as well as customer
    master. NAPP_CX_CSE_ASSETS_B is 34.3M rows of install base; labelling it
    Customer on prefix alone would point every customer question at it. The
    carve-out rules sit above Customer in the file and this pins that ordering.
    """
    store, _ = deployed_atp_ds
    role = store.role("analyst")
    got = store.authorize_object("ATP", "NAPPERPDS", obj, role)
    assert got.business_domain == domain


@pytest.mark.parametrize(
    "name", ["RUPD$_NAPP_CX_LOCATIONEXTRACTPVO", "RUPD$_NAPP_CX_PARTYSITEEXTRACTPVO"]
)
def test_materialized_view_refresh_artifacts_are_excluded(deployed_atp_ds, name):
    store, _ = deployed_atp_ds
    role = store.role("analyst")
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ATP", "NAPPERPDS", name, role)


def test_invalid_exclusion_regex_is_a_configuration_error(tmp_path: Path):
    policy = tmp_path / "bad.yaml"
    policy.write_text(
        "database: ATP\ndefault_schema: X\nschemas: []\n"
        "discovered_schemas: [X]\nexcluded_objects: ['[unclosed']\n",
        encoding="utf-8",
    )
    from oracle_mcp.errors import ConfigurationError
    from oracle_mcp.policy import load_database_policy

    with pytest.raises(ConfigurationError, match="Invalid regular expression"):
        load_database_policy(policy)
