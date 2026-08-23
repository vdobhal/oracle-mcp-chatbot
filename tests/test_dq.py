"""Data-quality metric, trend, history, and report tests."""

from __future__ import annotations

import json

import pytest

from oracle_mcp.dq import (
    DqHistory,
    calculate_metrics,
    render_markdown,
    severity_for,
    trend_from,
)
from oracle_mcp.errors import SqlValidationError


@pytest.mark.parametrize(
    ("rate", "expected"),
    [
        (10.01, "Critical"),
        (10.0, "High"),
        (5.0, "High"),
        (4.99, "Medium"),
        (1.0, "Medium"),
        (0.99, "Low"),
        (0.0, "Low"),
    ],
)
def test_severity_thresholds(rate, expected):
    assert severity_for(rate) == expected


def test_metrics_are_calculated_from_exact_counts():
    result = calculate_metrics(1000, 75)
    assert result == {
        "total_records": 1000,
        "failed_records": 75,
        "passed_records": 925,
        "pass_percentage": 92.5,
        "failure_percentage": 7.5,
        "severity": "High",
    }


def test_failed_records_cannot_exceed_total():
    with pytest.raises(ValueError, match="exceed"):
        calculate_metrics(2, 3)


def test_trend_flags_deterioration():
    trend = trend_from(8.5, {"failure_percentage": 5.0})
    assert trend["status"] == "DETERIORATED"
    assert trend["deteriorated"] is True
    assert trend["change_percentage_points"] == 3.5


def test_history_returns_latest_matching_execution(tmp_path):
    history = DqHistory(tmp_path / "dq.jsonl")
    history.append({"database": "ONPREM", "rule_id": "R1", "failure_percentage": 2})
    history.append({"database": "ATP", "rule_id": "R1", "failure_percentage": 8})
    history.append({"database": "ONPREM", "rule_id": "R1", "failure_percentage": 4})
    assert history.previous("onprem", "R1")["failure_percentage"] == 4


def test_report_contains_every_required_section():
    result = {
        "rule_id": "R-001",
        "rule_name": "Customer key is mandatory",
        "dimension": "Completeness",
        "reference_checkpoint": "Source contract section 4",
        "total_records": 100,
        "failed_records": 12,
        "pass_percentage": 88.0,
        "failure_percentage": 12.0,
        "severity": "Critical",
        "trend": {
            "status": "DETERIORATED",
            "deteriorated": True,
            "message": "Failure rate increased by 2.00 percentage points.",
        },
        "recommended_actions": ["Correct mandatory fields at source."],
    }
    report = render_markdown([result], "2026-08-23T00:00:00+00:00")
    for heading in (
        "Executive Summary",
        "DQ Score",
        "Critical Findings",
        "Trend Analysis",
        "Root Cause Analysis",
        "Recommended Actions",
        "Detailed Rule Results",
    ):
        assert f"# {heading}" in report
    assert "deteriorated" in report


def test_dml_metric_sql_is_rejected_before_execution(service, analyst, onprem_conn):
    with pytest.raises(SqlValidationError, match="rejected"):
        service._execute_dq_metric(  # noqa: SLF001 - security regression test
            "ONPREM",
            "DELETE FROM CDM_RPT.V_CUSTOMER_MASTER",
            "FAILED_RECORDS",
            analyst,
        )
    assert onprem_conn.executed == []
