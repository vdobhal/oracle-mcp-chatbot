"""Oracle connectivity for On-Prem and ATP.

One pooled connection per named profile. Every statement runs inside an explicit
``SET TRANSACTION READ ONLY`` block, which is the last line of defence: if a
write ever slipped past the SQL guard, Oracle itself raises ORA-01456 rather
than modifying data.

Timeouts are enforced by the driver (``connection.call_timeout``) rather than by
a Python-side wait, so a runaway query is actually cancelled in the database
instead of merely abandoned by the client.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

import oracledb

from .errors import (
    ConfigurationError,
    DatabaseUnavailableError,
    QueryExecutionError,
    QueryTimeoutError,
)
from .masking import to_json_safe
from .settings import OracleProfile

logger = logging.getLogger(__name__)

# CLOBs arrive as str instead of LOB locators, which keeps result serialisation
# simple and avoids extra round trips.
oracledb.defaults.fetch_lobs = False

_TIMEOUT_MARKERS = ("DPY-4024", "DPI-1067", "ORA-01013", "ORA-00040")
_UNAVAILABLE_MARKERS = (
    "DPY-6005", "DPY-6000", "ORA-12154", "ORA-12541", "ORA-12514",
    "ORA-01017", "ORA-28000", "ORA-12170", "ORA-28759",
)

# Oracle error text frequently embeds SQL fragments and bind values. Only the
# error code is ever surfaced; the full text goes to the server log alone.
_ORA_CODE = re.compile(r"\b((?:ORA|DPY|DPI)-\d{4,5})\b")

_thick_initialized = False
_thick_lock = threading.Lock()


def _ensure_thick_mode(profile: OracleProfile) -> None:
    global _thick_initialized
    if profile.mode != "thick":
        return
    with _thick_lock:
        if _thick_initialized:
            return
        kwargs: dict[str, Any] = {}
        if profile.lib_dir:
            kwargs["lib_dir"] = profile.lib_dir
        config_dir = profile.config_dir or profile.wallet_dir
        if config_dir:
            kwargs["config_dir"] = config_dir
        try:
            oracledb.init_oracle_client(**kwargs)
        except Exception as exc:  # noqa: BLE001 - surfaced as configuration error
            raise ConfigurationError(
                f"Thick mode requested for {profile.database_name} but the Oracle Client "
                f"libraries could not be initialised: {type(exc).__name__}"
            ) from exc
        _thick_initialized = True


def _classify(exc: Exception, database_name: str) -> Exception:
    """Translate a driver exception into a user-safe error, code only."""
    text = str(exc)
    code_match = _ORA_CODE.search(text)
    code = code_match.group(1) if code_match else type(exc).__name__

    if any(marker in text for marker in _TIMEOUT_MARKERS):
        return QueryTimeoutError(
            f"The query on {database_name} exceeded the allowed execution time and was "
            f"cancelled ({code}).",
            next_steps=[
                "Add a narrower filter, such as a shorter date range.",
                "Aggregate instead of listing individual rows.",
            ],
        )
    if any(marker in text for marker in _UNAVAILABLE_MARKERS):
        return DatabaseUnavailableError(
            f"{database_name} could not be reached or the service account could not "
            f"authenticate ({code}).",
            next_steps=[
                "Confirm the database service and network path are available.",
                "Ask the platform team to check the service account and wallet validity.",
            ],
        )
    return QueryExecutionError(
        f"{database_name} rejected the query ({code}).",
        next_steps=[
            "Re-check the column and table names with get_table_metadata.",
            "Simplify the query and retry.",
        ],
    )


class OracleConnection:
    """Lazily-created pool for one named database."""

    def __init__(self, profile: OracleProfile, *, query_timeout_seconds: int) -> None:
        self.profile = profile
        self.query_timeout_seconds = query_timeout_seconds
        self._pool: oracledb.ConnectionPool | None = None
        self._lock = threading.Lock()

    @property
    def database_name(self) -> str:
        return self.profile.database_name

    def _pool_or_create(self) -> oracledb.ConnectionPool:
        if self._pool is not None:
            return self._pool
        with self._lock:
            if self._pool is not None:
                return self._pool
            _ensure_thick_mode(self.profile)
            kwargs = self.profile.connect_kwargs()
            try:
                self._pool = oracledb.create_pool(**kwargs)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Pool creation failed for %s: %s", self.database_name, type(exc).__name__
                )
                raise _classify(exc, self.profile.display_name) from None
            finally:
                # Drop the plaintext password reference as soon as the pool holds it.
                kwargs.pop("password", None)
                kwargs.pop("wallet_password", None)
            logger.info(
                "Connection pool ready for %s (mode=%s, wallet=%s)",
                self.database_name,
                self.profile.mode,
                self.profile.uses_wallet,
            )
            return self._pool

    @contextmanager
    def read_only_cursor(self) -> Iterator[oracledb.Cursor]:
        """Acquire a connection pinned to a read-only transaction with a call timeout."""
        pool = self._pool_or_create()
        connection = None
        try:
            connection = pool.acquire()
            connection.call_timeout = self.query_timeout_seconds * 1000
            cursor = connection.cursor()
            cursor.arraysize = 200
            cursor.prefetchrows = 200
            try:
                cursor.execute("SET TRANSACTION READ ONLY")
                yield cursor
            finally:
                try:
                    connection.rollback()  # closes the read-only transaction
                except Exception:  # noqa: BLE001 - teardown must not mask the real error
                    logger.debug("Rollback failed on %s teardown", self.database_name)
                cursor.close()
        except oracledb.Error as exc:
            logger.warning("Oracle error on %s: %s", self.database_name, exc)
            raise _classify(exc, self.profile.display_name) from None
        finally:
            if connection is not None:
                try:
                    pool.release(connection)
                except Exception:  # noqa: BLE001
                    logger.debug("Connection release failed on %s", self.database_name)

    def fetch(
        self,
        sql: str,
        binds: dict[str, Any] | None = None,
        *,
        max_rows: int,
    ) -> tuple[list[str], list[dict[str, Any]], bool, float]:
        """Run a validated SELECT.

        Fetches ``max_rows + 1`` so truncation can be reported honestly rather
        than silently returning a short answer to a question about totals.
        """
        started = time.perf_counter()
        with self.read_only_cursor() as cursor:
            try:
                cursor.execute(sql, binds or {})
                columns = [d[0] for d in (cursor.description or [])]
                raw: Sequence[tuple[Any, ...]] = cursor.fetchmany(max_rows + 1)
            except oracledb.Error as exc:
                logger.warning("Query failed on %s: %s", self.database_name, exc)
                raise _classify(exc, self.profile.display_name) from None

        truncated = len(raw) > max_rows
        rows = [
            {col: to_json_safe(val) for col, val in zip(columns, record)}
            for record in raw[:max_rows]
        ]
        elapsed_ms = (time.perf_counter() - started) * 1000
        return columns, rows, truncated, elapsed_ms

    def plan_cost(self, sql: str, binds: dict[str, Any] | None = None) -> int | None:
        """Estimated plan cost, or None when PLAN_TABLE is unavailable.

        Best-effort by design: a missing PLAN_TABLE must not block queries, since
        this is an optimisation guard rather than a security control.
        """
        statement_id = f"mcp_{int(time.time() * 1000)}"
        try:
            with self.read_only_cursor() as cursor:
                cursor.execute(
                    f"EXPLAIN PLAN SET STATEMENT_ID = :sid FOR {sql}",
                    {**(binds or {}), "sid": statement_id},
                )
                cursor.execute(
                    "SELECT MAX(cost) FROM plan_table WHERE statement_id = :sid",
                    {"sid": statement_id},
                )
                row = cursor.fetchone()
                return int(row[0]) if row and row[0] is not None else None
        except Exception as exc:  # noqa: BLE001
            logger.debug("Plan cost unavailable on %s: %s", self.database_name, type(exc).__name__)
            return None

    def ping(self) -> bool:
        try:
            with self.read_only_cursor() as cursor:
                cursor.execute("SELECT 1 FROM dual")
                cursor.fetchone()
            return True
        except Exception:  # noqa: BLE001
            return False

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.close(force=True)
            finally:
                self._pool = None


class ConnectionRegistry:
    """All databases this server process serves, keyed by logical name."""

    def __init__(
        self, profiles: dict[str, OracleProfile], *, query_timeout_seconds: int
    ) -> None:
        self._connections: dict[str, OracleConnection] = {
            profile.database_name.upper(): OracleConnection(
                profile, query_timeout_seconds=query_timeout_seconds
            )
            for profile in profiles.values()
            if profile.enabled
        }

    def get(self, database_name: str) -> OracleConnection:
        conn = self._connections.get((database_name or "").strip().upper())
        if conn is None:
            known = ", ".join(sorted(self._connections)) or "none"
            raise DatabaseUnavailableError(
                f"Database {database_name!r} is not served by this MCP server. "
                f"Available: {known}.",
                next_steps=[f"Retry with one of: {known}"],
            )
        return conn

    @property
    def names(self) -> list[str]:
        return sorted(self._connections)

    def public_metadata(self) -> list[dict[str, Any]]:
        return [conn.profile.public_metadata() for conn in self._connections.values()]

    def close_all(self) -> None:
        for conn in self._connections.values():
            conn.close()
