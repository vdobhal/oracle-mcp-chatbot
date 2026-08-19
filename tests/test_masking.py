"""Masking tests."""

from __future__ import annotations

import pytest

from oracle_mcp.masking import Masker, luhn_valid, to_json_safe

pytestmark = pytest.mark.security


@pytest.fixture
def masker(store) -> Masker:
    return Masker(store.masking_config)


def mask_one(masker, row, role, **kwargs):
    rows, report = masker.mask_rows([row], role=role, **kwargs)
    return rows[0], report.masked_columns


# --------------------------------------------------------------------------- #
# Name-based rules
# --------------------------------------------------------------------------- #

def test_authentication_secrets_are_redacted_even_for_admin(masker, admin):
    row, report = mask_one(masker, {"USER_PASSWORD": "hunter2", "API_KEY": "sk-live-abc"}, admin)
    assert row["USER_PASSWORD"] == "[REDACTED]"
    assert row["API_KEY"] == "[REDACTED]"
    assert set(report) == {"USER_PASSWORD", "API_KEY"}


def test_tax_id_is_partially_masked_for_analyst(masker, analyst):
    row, _ = mask_one(masker, {"TAX_REGISTRATION_NUMBER": "GB123456789"}, analyst)
    assert row["TAX_REGISTRATION_NUMBER"] == "****6789"


def test_tax_id_is_visible_to_admin(masker, admin):
    row, _ = mask_one(masker, {"TAX_REGISTRATION_NUMBER": "GB123456789"}, admin)
    assert row["TAX_REGISTRATION_NUMBER"] == "GB123456789"


def test_email_is_masked_for_business_user_but_not_analyst(masker, business_user, analyst):
    masked, _ = mask_one(masker, {"PRIMARY_EMAIL": "jane.doe@example.com"}, business_user)
    assert masked["PRIMARY_EMAIL"] == "j***@example.com"

    visible, _ = mask_one(masker, {"PRIMARY_EMAIL": "jane.doe@example.com"}, analyst)
    assert visible["PRIMARY_EMAIL"] == "jane.doe@example.com"


def test_phone_is_masked_for_business_user(masker, business_user):
    row, _ = mask_one(masker, {"PRIMARY_PHONE": "+44 20 7946 0958"}, business_user)
    assert row["PRIMARY_PHONE"] == "***-***-0958"


def test_card_number_is_never_shown(masker, admin):
    row, _ = mask_one(masker, {"CREDIT_CARD_NUMBER": "4111111111111111"}, admin)
    assert row["CREDIT_CARD_NUMBER"] == "****1111"


def test_salary_is_redacted_for_analyst(masker, analyst):
    row, _ = mask_one(masker, {"ANNUAL_SALARY": 125000}, analyst)
    assert row["ANNUAL_SALARY"] == "[REDACTED]"


def test_nulls_stay_null_rather_than_becoming_a_mask_token(masker, business_user):
    row, _ = mask_one(masker, {"PRIMARY_EMAIL": None}, business_user)
    assert row["PRIMARY_EMAIL"] is None


# --------------------------------------------------------------------------- #
# Classification-based masking (the SELECT * backstop)
# --------------------------------------------------------------------------- #

def test_column_above_clearance_is_redacted_by_classification(masker, store, business_user):
    obj = store.database("ONPREM").resolve_object("CDM_RPT", "V_CUSTOMER_MASTER")
    row, report = mask_one(
        masker,
        {"CUSTOMER_ID": 1, "TAX_REGISTRATION_NUMBER": "GB123456789"},
        business_user,
        object_policy=obj,
    )
    assert row["CUSTOMER_ID"] == 1
    assert row["TAX_REGISTRATION_NUMBER"] == "[REDACTED]"
    assert "TAX_REGISTRATION_NUMBER" in report


def test_column_at_clearance_is_untouched(masker, store, analyst):
    obj = store.database("ONPREM").resolve_object("CDM_RPT", "V_CUSTOMER_MASTER")
    row, _ = mask_one(
        masker, {"CUSTOMER_NAME": "Acme Trading Ltd"}, analyst, object_policy=obj
    )
    assert row["CUSTOMER_NAME"] == "Acme Trading Ltd"


# --------------------------------------------------------------------------- #
# Content-based scanners
# --------------------------------------------------------------------------- #

def test_card_number_hidden_in_a_free_text_column_is_caught(masker, admin):
    row, report = mask_one(masker, {"NOTES": "card 4111111111111111 on file"}, admin)
    assert "4111111111111111" not in row["NOTES"]
    assert "NOTES" in report


def test_a_long_non_card_number_is_left_alone(masker, admin):
    row, report = mask_one(masker, {"NOTES": "order 1234567890123456"}, admin)
    assert row["NOTES"] == "order 1234567890123456"
    assert "NOTES" not in report


def test_ssn_in_free_text_is_redacted(masker, admin):
    row, _ = mask_one(masker, {"COMMENT_TEXT": "ssn 123-45-6789"}, admin)
    assert "123-45-6789" not in row["COMMENT_TEXT"]


def test_private_key_in_free_text_is_redacted(masker, admin):
    row, _ = mask_one(
        masker, {"CONFIG_BLOB": "-----BEGIN RSA PRIVATE KEY-----MIIE"}, admin
    )
    assert row["CONFIG_BLOB"] == "[REDACTED]"


def test_jwt_in_free_text_is_redacted(masker, admin):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P"
    row, _ = mask_one(masker, {"PAYLOAD": token}, admin)
    assert row["PAYLOAD"] == "[REDACTED]"


def test_long_strings_are_truncated(masker, admin):
    row, _ = mask_one(masker, {"DESCRIPTION": "x" * 5000}, admin)
    assert len(row["DESCRIPTION"]) < 500
    assert row["DESCRIPTION"].endswith("...[truncated]")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "number,expected",
    [("4111111111111111", True), ("4111111111111112", False), ("1234567890123456", False)],
)
def test_luhn(number, expected):
    assert luhn_valid(number) is expected


def test_json_conversion_of_driver_types():
    from datetime import datetime
    from decimal import Decimal

    assert to_json_safe(Decimal("10")) == 10
    assert to_json_safe(Decimal("10.5")) == 10.5
    assert to_json_safe(datetime(2026, 8, 19, 10, 30)) == "2026-08-19T10:30:00"
    assert to_json_safe(b"\x00\x01") == "<binary 2 bytes>"
