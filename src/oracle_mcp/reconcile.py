"""Cross-database reconciliation between On-Prem and ATP.

Both sides go through the full guardrail chain independently before either runs,
so a reconciliation request cannot be used to smuggle a query past validation by
hiding it in the second slot.

Comparison happens in Python on already-capped, already-masked result sets. That
keeps the two databases from having to trust each other and avoids the database
link that a SQL-side join would require.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from .errors import SqlValidationError

MAX_DETAIL_ROWS = 50
# Distinct-key comparisons load the whole key set. The ordinary row cap is a
# sample and cannot answer "how many keys are missing".
MAX_COMPARE_KEYS = 1_000_000
_INTEGER_TEXT = re.compile(r"[+-]?\d+")


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
    """Compare keys across NUMBER and VARCHAR2 storage.

    Trailing space and letter case are formatting noise. An On-Prem NUMBER and
    the same value stored as text on ATP (including leading zeros) are the same
    key. Booleans are left alone because ``bool`` is a subclass of ``int``.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, str):
        text = value.strip()
        if _INTEGER_TEXT.fullmatch(text):
            return str(int(text))
        return text.upper()
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


def summarize_site_mismatch_rows(
    rows: Sequence[dict[str, Any]],
    countries: dict[str, dict[str, Any]],
    *,
    limit: int = 10,
) -> dict[str, Any]:
    """Count End Customer versus Installed At site mismatches and attach CDM country.

    ``rows`` come from the On-Prem join. ``countries`` is keyed by address CMAT
    ID and holds ``country`` and ``company`` from ATP. A site with no CDM row
    is reported as missing rather than as a country.
    """
    same_country = 0
    different_country = 0
    missing_cdm = 0
    country_pairs: dict[tuple[str, str], int] = {}
    site_pairs: dict[tuple[str, str], int] = {}
    serials: set[str] = set()

    def label(site: str) -> tuple[str, str]:
        record = countries.get(site) or {}
        country = record.get("country")
        company = record.get("company") or ""
        if country in (None, ""):
            return "Not in CDM", company
        return str(country), str(company)

    for row in rows:
        serial = _normalize(row.get("SYSTEM_SERIAL_NUMBER"))
        if serial is not None:
            serials.add(str(serial))
        end_site = str(_normalize(row.get("END_CUSTOMER_SITE_ID")) or "")
        installed_site = str(_normalize(row.get("INSTALLED_AT_SITE_ID")) or "")
        end_country, end_company = label(end_site)
        installed_country, installed_company = label(installed_site)
        if end_country == "Not in CDM" or installed_country == "Not in CDM":
            missing_cdm += 1
        elif end_country == installed_country:
            same_country += 1
        else:
            different_country += 1
        country_key = (end_country, installed_country)
        country_pairs[country_key] = country_pairs.get(country_key, 0) + 1
        site_key = (end_site, installed_site, end_company, end_country, installed_company, installed_country)
        site_pairs[site_key] = site_pairs.get(site_key, 0) + 1

    def country_rows(predicate) -> list[dict[str, Any]]:
        ranked = sorted(
            (
                {"end_customer_country": key[0], "installed_at_country": key[1], "serials": count}
                for key, count in country_pairs.items()
                if predicate(key)
            ),
            key=lambda item: item["serials"],
            reverse=True,
        )
        return ranked[:limit]

    ranked_sites = sorted(site_pairs.items(), key=lambda item: item[1], reverse=True)[:limit]
    return {
        "mismatch_serials": len(serials) if serials else len(rows),
        "same_country_serials": same_country,
        "different_country_serials": different_country,
        "site_missing_from_cdm_serials": missing_cdm,
        "distinct_site_pairs": len(site_pairs),
        "top_same_country": country_rows(lambda key: key[0] == key[1] and key[0] != "Not in CDM"),
        "top_cross_country": country_rows(lambda key: key[0] != key[1]),
        "top_site_pairs": [
            {
                "serials": count,
                "end_customer_site_id": key[0],
                "end_customer": key[2],
                "end_customer_country": key[3],
                "installed_at_site_id": key[1],
                "installed_at": key[4],
                "installed_at_country": key[5],
            }
            for key, count in ranked_sites
        ],
    }


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


# Oracle rejects an IN list longer than 1000 expressions. The SQL guard rejects
# a statement longer than its configured maximum, so a large variant-site set is
# split into several statements that each stay under this size.
_IN_LIST_LIMIT = 1000
_MAX_VARIANT_SQL_CHARS = 18_000
ADDRESS_VARIANT_FLAG_VALUE = "true"


def numeric_site_ids(addresses: Sequence[dict[str, Any]]) -> list[int]:
    """Return distinct integer CMAT address IDs, matching On-Prem NUMBER sites."""
    found: set[int] = set()
    for row in addresses:
        key = _normalize(row.get("CMAT_ADDRESS_ID"))
        if isinstance(key, str) and key.lstrip("-").isdigit():
            found.add(int(key))
    return sorted(found)


def variant_site_count_sql(site_ids: Sequence[int]) -> str:
    """Count active End Customer serials on the supplied sites.

    The grand-total grouping row has a null ``CMAT_SITE_ID`` and is the distinct
    serial count. Per-site rows carry ``SERIALS`` for the CDM country breakdown.
    """
    ids = [int(site_id) for site_id in site_ids]
    if not ids:
        raise ValueError("variant site SQL requires at least one site id")
    predicates: list[str] = []
    for start in range(0, len(ids), _IN_LIST_LIMIT):
        batch = ", ".join(str(site_id) for site_id in ids[start:start + _IN_LIST_LIMIT])
        predicates.append(f"ec.cmat_site_id IN ({batch})")
    predicate = " OR ".join(predicates)
    return (
        "SELECT ec.cmat_site_id, COUNT(DISTINCT ec.system_serial_number) AS serials "
        "FROM eim.eim_pr_ib_latest ec "
        "JOIN eim.eim_pr_system s "
        "ON s.system_serial_number = ec.system_serial_number "
        "WHERE ec.role_id = 1 "
        f"AND ({predicate}) "
        "AND s.installed_product_status = 'ACTIVE' "
        "AND s.hardware_serv_end_date > SYSDATE "
        "GROUP BY GROUPING SETS ((ec.cmat_site_id), ())"
    )


def variant_site_count_statements(site_ids: Sequence[int]) -> list[str]:
    """One or more On-Prem statements, each short enough for the SQL guard."""
    ids = [int(site_id) for site_id in site_ids]
    if not ids:
        return []
    sql = variant_site_count_sql(ids)
    if len(sql) <= _MAX_VARIANT_SQL_CHARS or len(ids) == 1:
        return [sql]
    mid = len(ids) // 2
    return variant_site_count_statements(ids[:mid]) + variant_site_count_statements(ids[mid:])


def summarize_variant_site_groups(
    group_rows: Sequence[dict[str, Any]],
    addresses: Sequence[dict[str, Any]],
    *,
    limit: int = 25,
) -> dict[str, Any]:
    """Attach CDM company and country to End Customer sites on variant addresses.

    A null ``CMAT_SITE_ID`` row is the distinct serial total from ``GROUPING SETS``.
    When several statements were required, those totals are summed. The site
    lists are disjoint, so a serial is counted twice only if it has two End
    Customer role rows on variant sites that fell into different statements.
    """
    by_site: dict[str, dict[str, Any]] = {}
    for row in addresses:
        key = _normalize(row.get("CMAT_ADDRESS_ID"))
        if key is not None:
            by_site[str(key)] = row

    variant_serials = 0
    partitions = 0
    sites: list[dict[str, Any]] = []
    for row in group_rows:
        site = _normalize(row.get("CMAT_SITE_ID"))
        serials = int(row.get("SERIALS") or 0)
        if site is None:
            variant_serials += serials
            partitions += 1
            continue
        info = by_site.get(str(site), {})
        sites.append(
            {
                "serials": serials,
                "end_customer_site_id": str(site),
                "company_name": info.get("COMPANY_NAME"),
                "country": info.get("COUNTRY"),
                "company_variant_flag": info.get("COMPANY_VARIANT_FLAG"),
            }
        )
    if partitions == 0:
        variant_serials = sum(item["serials"] for item in sites)
    sites.sort(key=lambda item: (-item["serials"], item["end_customer_site_id"]))
    countries: dict[str, int] = {}
    company_variant_serials = 0
    for site in sites:
        country = site["country"] or "Unknown"
        countries[country] = countries.get(country, 0) + int(site["serials"])
        if str(site.get("company_variant_flag") or "").lower() == ADDRESS_VARIANT_FLAG_VALUE:
            company_variant_serials += int(site["serials"])
    country_rows = [
        {"country": country, "serials": count}
        for country, count in sorted(countries.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "variant_serials": variant_serials,
        "variant_sites_with_serials": len(sites),
        "cdm_variant_addresses": len(by_site),
        "site_partitions": partitions,
        "company_variant_serials": company_variant_serials,
        "top_sites": sites[:limit],
        "sites_omitted": max(0, len(sites) - limit),
        "serials_by_country": country_rows[:limit],
    }


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
