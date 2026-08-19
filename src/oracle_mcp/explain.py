"""Result profiling for the explanation tool.

Deliberately deterministic: it computes facts from the result set (counts,
nulls, distinct values, ranges, top values) and leaves the prose to the model.

That split is what stops the chatbot inventing numbers. The model never has to
derive "how many customers are missing a parent" from raw rows, because the
figure arrives pre-computed and is repeatable for the same input.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

MAX_TOP_VALUES = 5
_NUMERIC = (int, float)


def profile_rows(
    rows: Sequence[dict[str, Any]], columns: Sequence[str] | None = None
) -> dict[str, Any]:
    """Per-column facts for a result set."""
    if not rows:
        return {"row_count": 0, "columns": []}

    names = list(columns or rows[0].keys())
    profiles: list[dict[str, Any]] = []

    for name in names:
        values = [r.get(name) for r in rows]
        non_null = [v for v in values if v is not None]
        null_count = len(values) - len(non_null)

        profile: dict[str, Any] = {
            "column": name,
            "null_count": null_count,
            "null_percentage": round(100 * null_count / len(values), 1),
            "distinct_count": len({_hashable(v) for v in non_null}),
        }

        numeric = [v for v in non_null if isinstance(v, _NUMERIC) and not isinstance(v, bool)]
        if numeric and len(numeric) == len(non_null):
            profile["minimum"] = min(numeric)
            profile["maximum"] = max(numeric)
            profile["average"] = round(sum(numeric) / len(numeric), 4)
        elif non_null:
            comparable = [v for v in non_null if isinstance(v, str)]
            if comparable:
                profile["minimum"] = min(comparable)
                profile["maximum"] = max(comparable)

        if non_null and profile["distinct_count"] <= max(MAX_TOP_VALUES * 4, 20):
            counts = Counter(_hashable(v) for v in non_null)
            profile["top_values"] = [
                {"value": value, "count": count}
                for value, count in counts.most_common(MAX_TOP_VALUES)
            ]
        profiles.append(profile)

    return {"row_count": len(rows), "columns": profiles}


def _hashable(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool, type(None))) else str(value)


def key_observations(profile: dict[str, Any], truncated: bool, row_limit: int) -> list[str]:
    """Facts worth stating out loud, phrased for a business reader."""
    observations: list[str] = []
    row_count = profile.get("row_count", 0)

    if row_count == 0:
        return ["The query returned no rows."]

    observations.append(f"{row_count} row(s) were returned.")
    if truncated:
        observations.append(
            f"The result hit the {row_limit}-row cap, so this is a sample and totals are "
            "lower bounds. Use a COUNT query for an exact total."
        )

    for column in profile.get("columns", []):
        name = column["column"]
        if column["null_percentage"] >= 50:
            observations.append(
                f"{name} is empty in {column['null_percentage']}% of the returned rows."
            )
        elif column["null_count"] > 0:
            observations.append(
                f"{name} is empty in {column['null_count']} of {row_count} row(s)."
            )
        if column["distinct_count"] == 1 and row_count > 1:
            observations.append(f"{name} holds the same value in every returned row.")

    return observations


def data_quality_flags(profile: dict[str, Any]) -> list[str]:
    """Problems a data steward would want raised without being asked."""
    flags: list[str] = []
    row_count = profile.get("row_count", 0)
    if row_count == 0:
        return flags

    for column in profile.get("columns", []):
        name = column["column"]
        if column["null_percentage"] == 100:
            flags.append(f"{name} is empty in every returned row.")
        elif column["null_percentage"] >= 20:
            flags.append(
                f"{name} is missing in {column['null_percentage']}% of rows, which may "
                "indicate an incomplete load."
            )
        if name.upper().endswith(("_ID", "_NUMBER", "_KEY")) and row_count > 1:
            if column["distinct_count"] < row_count:
                duplicates = row_count - column["distinct_count"]
                flags.append(
                    f"{name} looks like an identifier but repeats: {duplicates} duplicate "
                    "value(s) across the returned rows."
                )
    return flags


def empty_result_reasons(sql: str, referenced_objects: Sequence[str]) -> list[str]:
    """Why an empty result is plausible, so the answer is useful rather than blank."""
    reasons = [
        "The filters may be narrower than intended, for example a date range that does "
        "not cover the period in question.",
        "The records may exist under a different status, source system or country code.",
    ]
    upper = sql.upper()
    if "SYSDATE" in upper or "CURRENT_DATE" in upper or "TRUNC" in upper:
        reasons.append(
            "The query is scoped to today. If the batch has not run yet, no rows will exist."
        )
    if referenced_objects:
        reasons.append(
            f"The data may live in a different object than {', '.join(referenced_objects)}."
        )
    reasons.append("The records may be filtered out by the underlying reporting view.")
    return reasons
