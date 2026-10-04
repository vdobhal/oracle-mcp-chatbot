"""Bounded in-memory caching and lightweight performance telemetry."""

from __future__ import annotations

import copy
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Any


@dataclass
class _CacheEntry:
    value: Any
    created_at: float
    expires_at: float


class TtlCache:
    """Thread-safe LRU/TTL cache.

    Values are copied on write and read so callers cannot mutate cached data.
    The caller owns key construction and must include every security boundary.
    """

    def __init__(self, *, enabled: bool, ttl_seconds: int, max_entries: int) -> None:
        self.enabled = enabled and ttl_seconds > 0 and max_entries > 0
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = RLock()

    def get(self, key: str) -> tuple[Any | None, float]:
        if not self.enabled:
            return None, 0.0
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None, 0.0
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None, 0.0
            self._entries.move_to_end(key)
            return copy.deepcopy(entry.value), max(0.0, now - entry.created_at)

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            self._entries[key] = _CacheEntry(
                value=copy.deepcopy(value),
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


class PerformanceMetrics:
    """Process-local counters suitable for health checks and dashboards."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._started_at = time.time()
        self._query_calls = 0
        self._database_calls = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._query_errors = 0
        self._slow_queries = 0
        self._database_ms_total = 0.0
        self._database_ms_max = 0.0
        self._by_database: dict[str, dict[str, float | int]] = {}

    def cache_hit(self, database: str) -> None:
        with self._lock:
            self._query_calls += 1
            self._cache_hits += 1
            self._database_bucket(database)["cache_hits"] += 1

    def cache_miss(self, database: str) -> None:
        with self._lock:
            self._query_calls += 1
            self._cache_misses += 1
            self._database_bucket(database)["cache_misses"] += 1

    def database_query(self, database: str, elapsed_ms: float, *, slow: bool) -> None:
        with self._lock:
            self._database_calls += 1
            self._database_ms_total += elapsed_ms
            self._database_ms_max = max(self._database_ms_max, elapsed_ms)
            if slow:
                self._slow_queries += 1
            bucket = self._database_bucket(database)
            bucket["database_calls"] += 1
            bucket["database_ms_total"] += elapsed_ms
            bucket["database_ms_max"] = max(float(bucket["database_ms_max"]), elapsed_ms)
            if slow:
                bucket["slow_queries"] += 1

    def query_error(self, database: str) -> None:
        with self._lock:
            self._query_errors += 1
            self._database_bucket(database)["query_errors"] += 1

    def snapshot(self, *, cache_entries: int) -> dict[str, Any]:
        with self._lock:
            hit_rate = (
                self._cache_hits / self._query_calls if self._query_calls else 0.0
            )
            average = (
                self._database_ms_total / self._database_calls
                if self._database_calls
                else 0.0
            )
            by_database = {
                name: {
                    **values,
                    "database_ms_total": round(float(values["database_ms_total"]), 1),
                    "database_ms_max": round(float(values["database_ms_max"]), 1),
                }
                for name, values in self._by_database.items()
            }
            return {
                "uptime_seconds": round(time.time() - self._started_at, 1),
                "query_calls": self._query_calls,
                "database_calls": self._database_calls,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "cache_hit_rate": round(hit_rate, 4),
                "cache_entries": cache_entries,
                "query_errors": self._query_errors,
                "slow_queries": self._slow_queries,
                "database_ms_total": round(self._database_ms_total, 1),
                "database_ms_average": round(average, 1),
                "database_ms_max": round(self._database_ms_max, 1),
                "by_database": by_database,
            }

    def _database_bucket(self, database: str) -> dict[str, float | int]:
        name = database.upper()
        if name not in self._by_database:
            self._by_database[name] = {
                "database_calls": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "query_errors": 0,
                "slow_queries": 0,
                "database_ms_total": 0.0,
                "database_ms_max": 0.0,
            }
        return self._by_database[name]
