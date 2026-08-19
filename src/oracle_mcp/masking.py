"""Data masking.

Applied to every row on the way out, after the database and before the model.
Two layers run unconditionally:

* name-based rules keyed on the column name, and
* content-based scanners that catch a secret sitting in an innocuously named
  column (a card number pasted into ``NOTES``, for example).

The scanners are the reason masking runs on values rather than being pushed
into the SQL: the guardrail cannot know what a free-text column contains.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Iterable, Sequence

from .policy import ColumnPolicy, ObjectPolicy, Role, sensitivity_rank

_REDACTED = "[REDACTED]"
_SUPPRESSED = "[SUPPRESSED]"


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def mask_last4(value: Any) -> str:
    text = str(value)
    tail = _digits(text)[-4:] or text[-4:]
    return f"****{tail}" if tail else _REDACTED


def mask_email(value: Any) -> str:
    text = str(value)
    if "@" not in text:
        return _REDACTED
    local, _, domain = text.partition("@")
    head = local[0] if local else ""
    return f"{head}***@{domain}"


def mask_phone(value: Any) -> str:
    tail = _digits(str(value))[-4:]
    return f"***-***-{tail}" if tail else _REDACTED


def mask_hash(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def mask_partial_name(value: Any) -> str:
    text = str(value).strip()
    if len(text) <= 1:
        return _REDACTED
    return f"{text[:3]}***" if len(text) > 3 else f"{text[0]}***"


def mask_date_year(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return str(value.year)
    match = re.search(r"\b(19|20)\d{2}\b", str(value))
    return match.group(0) if match else _REDACTED


def mask_redact(_value: Any) -> str:
    return _REDACTED


STRATEGIES = {
    "redact": mask_redact,
    "last4": mask_last4,
    "email": mask_email,
    "phone": mask_phone,
    "hash": mask_hash,
    "partial_name": mask_partial_name,
    "date_year": mask_date_year,
    "suppress": lambda _v: _SUPPRESSED,
}


def luhn_valid(number: str) -> bool:
    """Checksum used to keep long non-card digit strings (order IDs) unmasked."""
    digits = [int(c) for c in _digits(number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class MaskRule:
    name: str
    pattern: re.Pattern[str]
    strategy: str
    min_clearance: str
    min_clearance_rank: int
    reason: str
    luhn_check: bool = False

    def applies_to_role(self, clearance_rank: int) -> bool:
        """A role at or above the threshold sees the raw value.

        ``min_clearance`` of NEVER ranks above every clearance, so those rules
        always fire.
        """
        return clearance_rank < self.min_clearance_rank


@dataclass
class MaskingReport:
    masked_columns: dict[str, str]

    def as_list(self) -> list[dict[str, str]]:
        return [
            {"column": column, "reason": reason}
            for column, reason in sorted(self.masked_columns.items())
        ]


def _build_rules(entries: Iterable[dict[str, Any]], default_clearance: str) -> list[MaskRule]:
    rules: list[MaskRule] = []
    for entry in entries or []:
        strategy = str(entry.get("strategy", "redact"))
        if strategy not in STRATEGIES:
            raise ValueError(f"Unknown masking strategy: {strategy}")
        min_clearance = str(entry.get("min_clearance", default_clearance)).upper()
        rules.append(
            MaskRule(
                name=str(entry["name"]),
                pattern=re.compile(str(entry["pattern"])),
                strategy=strategy,
                min_clearance=min_clearance,
                min_clearance_rank=sensitivity_rank(min_clearance),
                reason=str(entry.get("reason", "Sensitive data")),
                luhn_check=bool(entry.get("luhn_check", False)),
            )
        )
    return rules


class Masker:
    """Applies name-based and content-based masking to result rows."""

    def __init__(self, masking_config: dict[str, Any]) -> None:
        self.column_rules = _build_rules(
            masking_config.get("column_patterns", []), default_clearance="NEVER"
        )
        self.value_rules = _build_rules(
            masking_config.get("value_scanners", []), default_clearance="NEVER"
        )
        self.max_string_length = int(masking_config.get("max_string_length", 400))

    # ---- column-level ------------------------------------------------------

    def column_rule_for(
        self,
        column_name: str,
        clearance_rank: int,
        *,
        qualified_name: str | None = None,
    ) -> MaskRule | None:
        haystacks = [column_name]
        if qualified_name:
            haystacks.append(qualified_name)
        for rule in self.column_rules:
            if not rule.applies_to_role(clearance_rank):
                continue
            if any(rule.pattern.search(h) for h in haystacks):
                return rule
        return None

    def infer_sensitivity(self, column_name: str, *, qualified_name: str | None = None) -> str:
        """Classify a column that the policy file does not declare.

        Objects allowlisted without an explicit column list get their columns from
        the data dictionary, so there is no hand-assigned sensitivity to enforce
        clearance against. The name-based masking rules already encode which column
        names are sensitive and how sensitive they are, so reuse that judgement here:
        the strictest matching rule becomes the column's classification. Without this
        the clearance check would silently pass every discovered column at INTERNAL.
        """
        best = "INTERNAL"
        best_rank = sensitivity_rank(best)
        for rule in self.column_rules:
            haystacks = [column_name] + ([qualified_name] if qualified_name else [])
            if any(rule.pattern.search(h) for h in haystacks):
                if rule.min_clearance_rank > best_rank:
                    best, best_rank = rule.min_clearance, rule.min_clearance_rank
        return best

    def policy_rule_for(
        self, column_policy: ColumnPolicy | None, clearance_rank: int
    ) -> MaskRule | None:
        """A column classified above the role's clearance is redacted outright.

        This is what stops ``SELECT *`` from leaking a RESTRICTED column that no
        name pattern happens to match.
        """
        if column_policy is None or column_policy.rank <= clearance_rank:
            return None
        return MaskRule(
            name="policy_classification",
            pattern=re.compile(r"^$"),
            strategy="redact",
            min_clearance=column_policy.sensitivity,
            min_clearance_rank=column_policy.rank,
            reason=f"Column classified {column_policy.sensitivity}; role clearance is lower.",
        )

    # ---- value-level -------------------------------------------------------

    def scan_value(self, value: Any, clearance_rank: int) -> tuple[Any, MaskRule | None]:
        if not isinstance(value, str) or not value:
            return value, None
        for rule in self.value_rules:
            if not rule.applies_to_role(clearance_rank):
                continue
            match = rule.pattern.search(value)
            if not match:
                continue
            if rule.luhn_check and not luhn_valid(match.group(0)):
                continue
            return STRATEGIES[rule.strategy](match.group(0)), rule
        return value, None

    # ---- row-level ---------------------------------------------------------

    def mask_rows(
        self,
        rows: Sequence[dict[str, Any]],
        *,
        role: Role,
        object_policy: ObjectPolicy | None = None,
        column_policies: dict[str, ColumnPolicy] | None = None,
    ) -> tuple[list[dict[str, Any]], MaskingReport]:
        clearance = role.clearance_rank
        report: dict[str, str] = {}
        lookup: dict[str, ColumnPolicy] = dict(column_policies or {})
        if object_policy:
            lookup.update({c.name.upper(): c for c in object_policy.columns})

        masked_rows: list[dict[str, Any]] = []
        for row in rows:
            out: dict[str, Any] = {}
            for column, value in row.items():
                key = column.upper()
                qualified = f"{object_policy.fqn}.{key}" if object_policy else key

                rule = self.policy_rule_for(lookup.get(key), clearance) or self.column_rule_for(
                    key, clearance, qualified_name=qualified
                )
                if rule is not None:
                    if rule.strategy == "suppress":
                        report[column] = rule.reason
                        continue
                    out[column] = None if value is None else STRATEGIES[rule.strategy](value)
                    report[column] = rule.reason
                    continue

                scanned, hit = self.scan_value(value, clearance)
                if hit is not None:
                    report[column] = hit.reason
                out[column] = self._truncate(scanned)
            masked_rows.append(out)
        return masked_rows, MaskingReport(report)

    def _truncate(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) > self.max_string_length:
            return value[: self.max_string_length] + "...[truncated]"
        return value


def to_json_safe(value: Any) -> Any:
    """Convert Oracle driver types into something JSON can carry."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        as_float = float(value)
        return int(value) if as_float.is_integer() else as_float
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return f"<binary {len(value)} bytes>"
    return str(value)
