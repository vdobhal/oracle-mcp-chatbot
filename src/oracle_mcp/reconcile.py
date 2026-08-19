"""Cross-database reconciliation between On-Prem and ATP.

Both sides go through the full guardrail chain independently before either runs,
so a reconciliation request cannot be used to smuggle a query past validation by
hiding it in the second slot.

Comparison happens in Python on already-capped, already-masked result sets. That
keeps the two databases from having to trust each other and avoids the database
link that a SQL-side join would require.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .errors import SqlValidationError

MAX_DETAIL_ROWS = 50


@dataclass
class SideResult:
    database: str
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool
    execution_ms: float
    sql: str


def _key_of(row: dict[str, Any], key_columns: Sequence[str]) -> tuple[Any, ...]:
    return tuple(_normalize(row.get(col)) for col in key_columns)


def _normalize(value: Any) -> Any:
    """Compare case- and whitespace-insensitively for text keys.

    Trailing-space and case differences between a legacy on-prem system and a
    cloud target are formatting noise, not genuine data breaks, and reporting
    them as mismatches buries the real ones.
    """
    if isinstance(value, str):
        return value.strip().upper()
    return value


def _resolve_key_columns(matching_key: str, rows: Sequence[dict[str, Any]]) -> list[str]:
    requested = [k.strip().upper() for k in matching_key.split(",") if k.strip()]
    if not requested:
        raise SqlValidationError(
            "A matching key column is required for reconciliation.",
            next_steps=["Supply a business key such as CUSTOMER_NUMBER."],
        )
    if not rows:
        return requested
    available = {k.upper() for k in rows[0]}
    missing = [k for k in requested if k not in available]
    if missing:
        raise SqlValidationError(
            f"Matching key column(s) {', '.join(missing)} are not present in the query "
            f"results. Available columns: {', '.join(sorted(available))}.",
            next_steps=["Include the matching key in the SELECT list on both sides."],
        )
    return requested


def compare_result_sets(
    *,
    business_entity: str,
    matching_key: str,
    source: SideResult,
    target: SideResult,
    compare_columns: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Set-compare two result sets and describe the differences in business terms."""
    key_columns = _resolve_key_columns(matching_key, source.rows or target.rows)

    source_index = {_key_of(r, key_columns): r for r in source.rows}
    target_index = {_key_of(r, key_columns): r for r in target.rows}

    source_keys = set(source_index)
    target_keys = set(target_index)
    common = source_keys & target_keys
    source_only = source_keys - target_keys
    target_only = target_keys - source_keys

    if compare_columns:
        attributes = [c.strip().upper() for c in compare_columns if c.strip()]
    else:
        attributes = sorted(
            ({k.upper() for k in (source.rows[0] if source.rows else {})}
             & {k.upper() for k in (target.rows[0] if target.rows else {})})
            - set(key_columns)
        )

    mismatches: list[dict[str, Any]] = []
    for key in sorted(common, key=lambda k: tuple(str(p) for p in k)):
        src_row, tgt_row = source_index[key], target_index[key]
        differences = {
            attr: {
                "onprem_value": src_row.get(attr),
                "atp_value": tgt_row.get(attr),
            }
            for attr in attributes
            if _normalize(src_row.get(attr)) != _normalize(tgt_row.get(attr))
        }
        if differences:
            mismatches.append(
                {
                    "key": dict(zip(key_columns, key)),
                    "differing_attributes": differences,
                }
            )

    matched = len(common) - len(mismatches)
    truncated = source.truncated or target.truncated

    return {
        "business_entity": business_entity,
        "matching_key": key_columns,
        "compared_attributes": attributes,
        "summary": {
            "source_row_count": source.row_count,
            "target_row_count": target.row_count,
            "matched_records": matched,
            "unmatched_records": len(source_only) + len(target_only) + len(mismatches),
            "source_only_count": len(source_only),
            "target_only_count": len(target_only),
            "attribute_mismatch_count": len(mismatches),
        },
        "source_only_records": [
            dict(zip(key_columns, key))
            for key in sorted(source_only, key=lambda k: tuple(str(p) for p in k))
        ][:MAX_DETAIL_ROWS],
        "target_only_records": [
            dict(zip(key_columns, key))
            for key in sorted(target_only, key=lambda k: tuple(str(p) for p in k))
        ][:MAX_DETAIL_ROWS],
        "mismatch_details": mismatches[:MAX_DETAIL_ROWS],
        "data_source_used": {
            "onprem": {
                "database": source.database,
                "row_count": source.row_count,
                "execution_ms": round(source.execution_ms, 1),
                "truncated": source.truncated,
            },
            "atp": {
                "database": target.database,
                "row_count": target.row_count,
                "execution_ms": round(target.execution_ms, 1),
                "truncated": target.truncated,
            },
        },
        "summary_recommendation": _recommend(
            len(source_only), len(target_only), len(mismatches), truncated
        ),
        "limitations": _limitations(truncated, source, target),
    }


def _recommend(source_only: int, target_only: int, mismatches: int, truncated: bool) -> str:
    if truncated:
        return (
            "One or both result sets hit the row cap, so these figures describe a sample "
            "rather than the full population. Narrow the filters and re-run before drawing "
            "a conclusion."
        )
    if not (source_only or target_only or mismatches):
        return "Both systems agree across every compared record and attribute."

    parts: list[str] = []
    if source_only:
        parts.append(
            f"{source_only} record(s) exist only on-prem, which usually means the "
            "integration has not delivered them yet or they were rejected on load."
        )
    if target_only:
        parts.append(
            f"{target_only} record(s) exist only in ATP, which usually means a delete or "
            "merge on-prem was not propagated."
        )
    if mismatches:
        parts.append(
            f"{mismatches} record(s) exist on both sides but hold different values, which "
            "points to a stale or partially applied update."
        )
    parts.append("Check the integration status and reject logs for the same batch window.")
    return " ".join(parts)


def _limitations(truncated: bool, source: SideResult, target: SideResult) -> list[str]:
    notes: list[str] = []
    if truncated:
        notes.append(
            "Result sets were capped by the row limit, so counts are lower bounds."
        )
    if not source.rows:
        notes.append("The on-prem query returned no rows.")
    if not target.rows:
        notes.append("The ATP query returned no rows.")
    notes.append(
        "Comparison ignores case and surrounding whitespace on text keys and attributes."
    )
    notes.append(
        f"At most {MAX_DETAIL_ROWS} example records are listed per difference category."
    )
    return notes
