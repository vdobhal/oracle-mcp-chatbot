"""Policy, RBAC and credential-isolation tests."""

from __future__ import annotations

import json

import pytest

from oracle_mcp.errors import AccessDeniedError, ObjectNotAllowlistedError, UnknownRoleError

pytestmark = pytest.mark.security


def test_roles_load_with_expected_clearances(store):
    assert store.role("business_user").clearance == "INTERNAL"
    assert store.role("analyst").clearance == "CONFIDENTIAL"
    assert store.role("admin").clearance == "RESTRICTED"
    assert store.default_role_name == "business_user"


def test_unknown_role_is_rejected(store):
    with pytest.raises(UnknownRoleError):
        store.role("superuser")


def test_missing_role_falls_back_to_the_weakest_role(store):
    assert store.role(None).name == "business_user"


def test_role_cannot_reach_a_schema_outside_its_grant(store, business_user):
    with pytest.raises(AccessDeniedError):
        store.authorize_object("ONPREM", "CDM", "CUSTOMER", business_user)


def test_object_outside_the_allowlist_is_rejected(store, admin):
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("ONPREM", "CDM_RPT", "V_DOES_NOT_EXIST", admin)


def test_unknown_database_is_rejected(store, admin):
    with pytest.raises(ObjectNotAllowlistedError):
        store.authorize_object("WAREHOUSE", "CDM_RPT", "V_CUSTOMER_MASTER", admin)


def test_restricted_column_is_denied_below_clearance(store, analyst):
    obj = store.authorize_object("ONPREM", "CDM_RPT", "V_CUSTOMER_MASTER", analyst)
    with pytest.raises(AccessDeniedError):
        store.authorize_column(obj, "TAX_REGISTRATION_NUMBER", analyst)


def test_effective_row_limit_takes_the_tighter_of_role_and_server(store):
    business_user = store.role("business_user")
    assert store.effective_max_rows(business_user, 500) == 200
    assert store.effective_max_rows(business_user, 50) == 50


def test_denial_messages_do_not_disclose_object_existence(store, business_user):
    """Both denial paths must read the same, or the error becomes a schema oracle."""
    try:
        store.authorize_object("ONPREM", "CDM", "CUSTOMER", business_user)
    except AccessDeniedError as exc:
        real_object_message = str(exc)

    try:
        store.authorize_object("ONPREM", "CDM", "TOTALLY_MADE_UP", business_user)
    except (AccessDeniedError, ObjectNotAllowlistedError) as exc:
        fake_object_message = str(exc)

    assert "CUSTOMER" not in real_object_message
    assert "TOTALLY_MADE_UP" not in fake_object_message or "not an approved" in fake_object_message


def test_allowed_objects_are_filtered_by_clearance(store):
    business_objects = {o.fqn for o in store.allowed_objects("ONPREM", store.role("business_user"))}
    analyst_objects = {o.fqn for o in store.allowed_objects("ONPREM", store.role("analyst"))}
    assert "CDM.CUSTOMER" not in business_objects
    assert "CDM.CUSTOMER" in analyst_objects
    assert business_objects < analyst_objects


def test_atp_and_onprem_policies_are_isolated(store):
    onprem = {o.fqn for o in store.database("ONPREM").iter_objects()}
    atp = {o.fqn for o in store.database("ATP").iter_objects()}
    assert not (onprem & atp)


# --------------------------------------------------------------------------- #
# Credential isolation
# --------------------------------------------------------------------------- #

def test_password_never_appears_in_repr_or_serialisation(oracle_profile):
    secret = "super-secret-password"
    assert secret not in repr(oracle_profile)
    assert secret not in str(oracle_profile)
    assert secret not in oracle_profile.model_dump_json()


def test_public_metadata_excludes_every_secret_bearing_field(oracle_profile):
    payload = oracle_profile.public_metadata()
    serialised = json.dumps(payload)
    assert "super-secret-password" not in serialised
    assert "db.internal" not in serialised  # hostname is infrastructure detail
    for forbidden in ("password", "wallet_password", "dsn", "host", "user"):
        assert forbidden not in payload


def test_connect_kwargs_unwrap_secrets_only_on_demand(oracle_profile):
    kwargs = oracle_profile.connect_kwargs()
    assert kwargs["password"] == "super-secret-password"
    assert kwargs["dsn"] == "db.internal:1521/CDMPRD"


def test_atp_wallet_profile_builds_thin_mode_arguments():
    from pydantic import SecretStr

    from oracle_mcp.settings import OracleProfile

    profile = OracleProfile(
        profile="atp",
        database_name="ATP",
        display_name="Oracle ATP",
        user="CHATBOT_RO",
        password=SecretStr("db-pw"),
        dsn="myatp_low",
        wallet_dir="/opt/oracle/wallets/atp",
        config_dir="/opt/oracle/wallets/atp",
        wallet_password=SecretStr("wallet-pw"),
        mode="thin",
    )
    kwargs = profile.connect_kwargs()
    assert kwargs["config_dir"] == "/opt/oracle/wallets/atp"
    assert kwargs["wallet_location"] == "/opt/oracle/wallets/atp"
    assert kwargs["wallet_password"] == "wallet-pw"
    assert profile.public_metadata()["tls"] == "mTLS (wallet)"


def test_thick_mode_rejects_a_wallet_password():
    from pydantic import SecretStr, ValidationError

    from oracle_mcp.settings import OracleProfile

    with pytest.raises(ValidationError):
        OracleProfile(
            profile="atp",
            database_name="ATP",
            display_name="Oracle ATP",
            user="CHATBOT_RO",
            password=SecretStr("db-pw"),
            dsn="myatp_low",
            wallet_dir="/opt/oracle/wallets/atp",
            wallet_password=SecretStr("wallet-pw"),
            mode="thick",
        )


def test_profile_without_a_dsn_is_rejected():
    from pydantic import SecretStr, ValidationError

    from oracle_mcp.settings import OracleProfile

    with pytest.raises(ValidationError):
        OracleProfile(
            profile="onprem",
            database_name="ONPREM",
            display_name="On-Prem",
            user="CHATBOT_RO",
            password=SecretStr("pw"),
        )
