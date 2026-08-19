"""Cross-database reconciliation tests."""

from __future__ import annotations

import pytest

from oracle_mcp.errors import SqlValidationError
from oracle_mcp.reconcile import SideResult, compare_result_sets

ONPREM_SQL = "SELECT customer_number, customer_status FROM CDM_RPT.V_CUSTOMER_MASTER"
ATP_SQL = "SELECT customer_number, customer_status FROM ATP_RPT.V_CUSTOMER_MASTER"


def side(database: str, rows, truncated: bool = False) -> SideResult:
    return SideResult(
        database=database,
        rows=rows,
        row_count=len(rows),
        truncated=truncated,
        execution_ms=10.0,
        sql="SELECT 1",
    )


def test_identical_sets_report_full_agreement():
    rows = [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "ACTIVE"}]
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side("On-Prem", rows),
        target=side("ATP", list(rows)),
    )
    assert result["summary"]["matched_records"] == 1
    assert result["summary"]["unmatched_records"] == 0
    assert "agree" in result["summary_recommendation"]


def test_source_only_and_target_only_records_are_separated():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side("On-Prem", [{"CUSTOMER_NUMBER": "C1"}, {"CUSTOMER_NUMBER": "C2"}]),
        target=side("ATP", [{"CUSTOMER_NUMBER": "C2"}, {"CUSTOMER_NUMBER": "C3"}]),
    )
    summary = result["summary"]
    assert summary["source_only_count"] == 1
    assert summary["target_only_count"] == 1
    assert summary["matched_records"] == 1
    assert result["source_only_records"] == [{"CUSTOMER_NUMBER": "C1"}]
    assert result["target_only_records"] == [{"CUSTOMER_NUMBER": "C3"}]


def test_attribute_mismatches_are_detailed():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side("On-Prem", [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "ACTIVE"}]),
        target=side("ATP", [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "INACTIVE"}]),
    )
    assert result["summary"]["attribute_mismatch_count"] == 1
    detail = result["mismatch_details"][0]
    assert detail["key"] == {"CUSTOMER_NUMBER": "C1"}
    assert detail["differing_attributes"]["CUSTOMER_STATUS"] == {
        "onprem_value": "ACTIVE",
        "atp_value": "INACTIVE",
    }


def test_case_and_whitespace_differences_are_not_treated_as_mismatches():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side("On-Prem", [{"CUSTOMER_NUMBER": " c1 ", "CUSTOMER_STATUS": "active"}]),
        target=side("ATP", [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "ACTIVE"}]),
    )
    assert result["summary"]["matched_records"] == 1
    assert result["summary"]["attribute_mismatch_count"] == 0


def test_composite_matching_keys_are_supported():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER, COUNTRY_CODE",
        source=side("On-Prem", [{"CUSTOMER_NUMBER": "C1", "COUNTRY_CODE": "GB"}]),
        target=side("ATP", [{"CUSTOMER_NUMBER": "C1", "COUNTRY_CODE": "US"}]),
    )
    assert result["matching_key"] == ["CUSTOMER_NUMBER", "COUNTRY_CODE"]
    assert result["summary"]["source_only_count"] == 1
    assert result["summary"]["target_only_count"] == 1


def test_missing_matching_key_is_rejected():
    with pytest.raises(SqlValidationError):
        compare_result_sets(
            business_entity="Customer master",
            matching_key="CUSTOMER_NUMBER",
            source=side("On-Prem", [{"CUSTOMER_ID": 1}]),
            target=side("ATP", [{"CUSTOMER_ID": 1}]),
        )


def test_truncated_input_downgrades_the_recommendation():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side("On-Prem", [{"CUSTOMER_NUMBER": "C1"}], truncated=True),
        target=side("ATP", [{"CUSTOMER_NUMBER": "C1"}]),
    )
    assert "sample" in result["summary_recommendation"]
    assert any("lower bound" in note for note in result["limitations"])


def test_compare_columns_narrows_the_comparison():
    result = compare_result_sets(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        source=side(
            "On-Prem", [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "A", "LOAD_DATE": "x"}]
        ),
        target=side(
            "ATP", [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "A", "LOAD_DATE": "y"}]
        ),
        compare_columns=["CUSTOMER_STATUS"],
    )
    assert result["compared_attributes"] == ["CUSTOMER_STATUS"]
    assert result["summary"]["attribute_mismatch_count"] == 0


# --------------------------------------------------------------------------- #
# Tool-level behaviour
# --------------------------------------------------------------------------- #

def test_reconciliation_validates_both_sides_before_running_either(service, onprem_conn, atp_conn):
    payload = service.compare_onprem_and_atp_data(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        onprem_query=ONPREM_SQL,
        atp_query="DELETE FROM ATP_RPT.V_CUSTOMER_MASTER",
        user_role="admin",
    )
    assert payload["status"] == "ERROR"
    assert onprem_conn.executed == []
    assert atp_conn.executed == []


def test_reconciliation_runs_end_to_end(service, onprem_conn, atp_conn):
    onprem_conn.set_result(
        ["CUSTOMER_NUMBER", "CUSTOMER_STATUS"],
        [
            {"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "ACTIVE"},
            {"CUSTOMER_NUMBER": "C2", "CUSTOMER_STATUS": "ACTIVE"},
        ],
    )
    atp_conn.set_result(
        ["CUSTOMER_NUMBER", "CUSTOMER_STATUS"],
        [{"CUSTOMER_NUMBER": "C1", "CUSTOMER_STATUS": "INACTIVE"}],
    )
    payload = service.compare_onprem_and_atp_data(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        onprem_query=ONPREM_SQL,
        atp_query=ATP_SQL,
        user_role="admin",
    )
    assert payload["status"] == "OK"
    assert payload["summary"]["source_only_count"] == 1
    assert payload["summary"]["attribute_mismatch_count"] == 1
    assert payload["data_source_used"]["onprem"]["database"] == "On-Prem Oracle DB"
    assert payload["data_source_used"]["atp"]["database"] == "Oracle ATP"


def test_business_user_may_not_reconcile(service):
    payload = service.compare_onprem_and_atp_data(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        onprem_query=ONPREM_SQL,
        atp_query=ATP_SQL,
        user_role="business_user",
    )
    assert payload["status"] == "ERROR"
    assert payload["error_code"] == "ACCESS_DENIED"


def test_reconciliation_is_unavailable_on_a_single_database_server(
    settings, store, registry, audit_logger
):
    from oracle_mcp.tools import ToolService

    single = settings.model_copy(update={"profile": "onprem"})
    service = ToolService(settings=single, store=store, registry=registry, audit=audit_logger)
    payload = service.compare_onprem_and_atp_data(
        business_entity="Customer master",
        matching_key="CUSTOMER_NUMBER",
        onprem_query=ONPREM_SQL,
        atp_query=ATP_SQL,
        user_role="admin",
    )
    assert payload["status"] == "ERROR"
    assert "single database" in payload["message"]
