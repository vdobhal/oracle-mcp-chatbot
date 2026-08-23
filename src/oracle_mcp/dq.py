"""Data-quality scoring, trend history, and business-friendly reporting.

Database access stays in :mod:`oracle_mcp.tools`; this module is deliberately
pure apart from the append-only local history store so calculations can be
tested without Oracle.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def severity_for(failure_percentage: float) -> str:
    """Apply the governed thresholds, assigning boundary values upward."""
    if failure_percentage > 10:
        return "Critical"
    if failure_percentage >= 5:
        return "High"
    if failure_percentage >= 1:
        return "Medium"
    return "Low"


def calculate_metrics(total_records: int, failed_records: int) -> dict[str, Any]:
    total = int(total_records)
    failed = int(failed_records)
    if total < 0 or failed < 0:
        raise ValueError("Record counts cannot be negative.")
    if failed > total:
        raise ValueError("Failed records cannot exceed total records.")
    failure_percentage = (failed / total * 100) if total else 0.0
    pass_percentage = 100.0 - failure_percentage if total else 100.0
    return {
        "total_records": total,
        "failed_records": failed,
        "passed_records": total - failed,
        "pass_percentage": round(pass_percentage, 2),
        "failure_percentage": round(failure_percentage, 2),
        "severity": severity_for(failure_percentage),
    }


class DqHistory:
    """Append-only JSONL history used for previous-run trend comparison."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def previous(self, database: str, rule_id: str) -> dict[str, Any] | None:
        if not self.path.is_file():
            return None
        latest: dict[str, Any] | None = None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if (
                        str(row.get("database", "")).upper() == database.upper()
                        and str(row.get("rule_id", "")) == str(rule_id)
                    ):
                        latest = row
        except OSError:
            return None
        return latest

    def append(self, result: dict[str, Any]) -> None:
        payload = json.dumps(result, ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(payload + "\n")
                handle.flush()


def trend_from(
    current_failure_percentage: float,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    if previous is None:
        return {
            "status": "BASELINE",
            "deteriorated": False,
            "change_percentage_points": None,
            "message": "This is the first recorded execution; it establishes the baseline.",
        }
    old = float(previous.get("failure_percentage") or 0)
    delta = round(current_failure_percentage - old, 2)
    if delta > 0:
        status = "DETERIORATED"
        message = f"Failure rate increased by {delta:.2f} percentage points."
    elif delta < 0:
        status = "IMPROVED"
        message = f"Failure rate improved by {abs(delta):.2f} percentage points."
    else:
        status = "STABLE"
        message = "Failure rate is unchanged from the previous execution."
    return {
        "status": status,
        "deteriorated": delta > 0,
        "change_percentage_points": delta,
        "previous_failure_percentage": round(old, 2),
        "message": message,
    }


def recommended_actions(result: dict[str, Any]) -> list[str]:
    severity = result["severity"]
    dimension = str(result.get("dimension") or "").lower()
    actions: list[str] = []
    if severity == "Critical":
        actions.append(
            "Open an immediate data-owner incident, pause affected downstream consumption, "
            "and agree a remediation deadline."
        )
    elif severity == "High":
        actions.append(
            "Assign the issue to the accountable data steward and remediate before the next "
            "scheduled load."
        )
    elif severity == "Medium":
        actions.append(
            "Add the issue to the current governance backlog and monitor the next execution."
        )
    else:
        actions.append(
            "Continue monitoring and correct the small exception population through normal "
            "stewardship."
        )
    if "complete" in dimension or "null" in dimension:
        actions.append("Make mandatory-field validation explicit at the source capture point.")
    if "duplicate" in dimension or "unique" in dimension:
        actions.append("Review match keys and introduce duplicate prevention before ingestion.")
    if "reference" in dimension or "integrity" in dimension:
        actions.append(
            "Synchronize reference data and quarantine records whose parent or lookup value "
            "cannot be resolved."
        )
    if result.get("trend", {}).get("deteriorated"):
        actions.append(
            "Compare the latest source and deployment changes with the deterioration window."
        )
    return actions


def render_markdown(results: list[dict[str, Any]], generated_at: str | None = None) -> str:
    generated_at = generated_at or utc_now()
    total = sum(int(row["total_records"]) for row in results)
    failed = sum(int(row["failed_records"]) for row in results)
    score = calculate_metrics(total, failed)
    critical = [row for row in results if row["severity"] == "Critical"]
    deteriorated = [row for row in results if row.get("trend", {}).get("deteriorated")]

    lines = [
        "# Executive Summary",
        "",
        (
            f"{len(results)} active data-quality rule(s) were evaluated at {generated_at}. "
            f"The overall DQ score is **{score['pass_percentage']:.2f}%**; "
            f"{failed:,} of {total:,} records failed."
        ),
        "",
        "# DQ Score",
        "",
        f"- Overall pass percentage: **{score['pass_percentage']:.2f}%**",
        f"- Overall failure percentage: **{score['failure_percentage']:.2f}%**",
        f"- Overall severity: **{score['severity']}**",
        "",
        "# Critical Findings",
        "",
    ]
    if critical:
        lines.extend(
            f"- **{row['rule_id']} — {row['rule_name']}**: "
            f"{row['failure_percentage']:.2f}% failure rate."
            for row in critical
        )
    else:
        lines.append("- No critical findings were identified.")

    lines.extend(["", "# Trend Analysis", ""])
    if deteriorated:
        lines.extend(
            f"- **{row['rule_id']}** deteriorated: {row['trend']['message']}"
            for row in deteriorated
        )
    else:
        lines.append("- No deterioration was detected against available previous runs.")

    lines.extend(["", "# Root Cause Analysis", ""])
    for row in results:
        checkpoint = row.get("reference_checkpoint") or "No reference checkpoint was supplied."
        lines.append(
            f"- **{row['rule_id']}**: The failure pattern relates to "
            f"{row.get('dimension') or 'the governed rule dimension'}. "
            f"Reference checkpoint: {checkpoint}"
        )

    lines.extend(["", "# Recommended Actions", ""])
    actions: list[str] = []
    for row in results:
        for action in row.get("recommended_actions") or recommended_actions(row):
            if action not in actions:
                actions.append(action)
    lines.extend(f"- {action}" for action in actions)

    lines.extend(["", "# Detailed Rule Results", ""])
    lines.append(
        "| Rule | Dimension | Total | Failed | Pass % | Failure % | Severity | Trend |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---|---|")
    for row in results:
        lines.append(
            f"| {row['rule_id']} — {row['rule_name']} | {row.get('dimension') or 'N/A'} | "
            f"{row['total_records']:,} | {row['failed_records']:,} | "
            f"{row['pass_percentage']:.2f}% | {row['failure_percentage']:.2f}% | "
            f"{row['severity']} | {row['trend']['status']} |"
        )
    return "\n".join(lines)
