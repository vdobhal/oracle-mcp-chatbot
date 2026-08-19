"""Shared fixtures.

Everything here runs without an Oracle instance. ``FakeConnection`` stands in
for the driver so the guardrail, masking and audit paths can be exercised
deterministically; tests that genuinely need a database are marked
``integration`` and skipped by default.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oracle_mcp.audit import AuditLogger  # noqa: E402
from oracle_mcp.policy import PolicyStore, clear_policy_cache  # noqa: E402
from oracle_mcp.settings import OracleProfile, Settings  # noqa: E402
from oracle_mcp.sql_guard import SqlGuard  # noqa: E402
from oracle_mcp.tools import ToolService  # noqa: E402

# Tests run against their own fixture policy, not the deployed allowlist in
# config/policy. Asserting on real allowlists would mean every governance change
# breaks the suite, and would make the tests describe one environment's contents
# rather than the behaviour of the access model itself.
POLICY_DIR = ROOT / "tests" / "policy"
DISCOVERY_POLICY_DIR = ROOT / "tests" / "policy_discovery"
DEPLOYED_POLICY_DIR = ROOT / "config" / "policy"


@pytest.fixture(scope="session")
def policy_dir() -> Path:
    """Fully declared allowlist: named objects with named, classified columns."""
    return POLICY_DIR


@pytest.fixture(scope="session")
def discovery_policy_dir() -> Path:
    """Allowlist that leans on the data dictionary, as the deployment does."""
    return DISCOVERY_POLICY_DIR


@pytest.fixture(scope="session")
def deployed_policy_dir() -> Path:
    return DEPLOYED_POLICY_DIR


@pytest.fixture
def store(policy_dir: Path) -> PolicyStore:
    clear_policy_cache()
    return PolicyStore(policy_dir, {"ONPREM": "onprem.yaml", "ATP": "atp.yaml"})


@pytest.fixture
def guard(store: PolicyStore) -> SqlGuard:
    return SqlGuard(store, max_rows=500, max_sql_length=20_000, allow_cartesian=False)


@pytest.fixture
def analyst(store: PolicyStore):
    return store.role("analyst")


@pytest.fixture
def business_user(store: PolicyStore):
    return store.role("business_user")


@pytest.fixture
def admin(store: PolicyStore):
    return store.role("admin")


class FakeProfile:
    def __init__(self, database_name: str, display_name: str) -> None:
        self.database_name = database_name
        self.display_name = display_name

    def public_metadata(self) -> dict[str, Any]:
        return {"database_name": self.database_name, "display_name": self.display_name}


class FakeConnection:
    """Records the SQL it was asked to run and replays canned rows."""

    def __init__(self, database_name: str, display_name: str) -> None:
        self.profile = FakeProfile(database_name, display_name)
        self.database_name = database_name
        self.rows: list[dict[str, Any]] = []
        self.columns: list[str] = []
        self.executed: list[tuple[str, dict[str, Any]]] = []
        self.truncate = False
        self.raises: Exception | None = None

    def set_result(self, columns: list[str], rows: list[dict[str, Any]]) -> None:
        self.columns = columns
        self.rows = rows

    def fetch(self, sql: str, binds: dict[str, Any] | None = None, *, max_rows: int):
        self.executed.append((sql, dict(binds or {})))
        if self.raises is not None:
            raise self.raises
        rows = self.rows[:max_rows]
        return self.columns or (list(rows[0].keys()) if rows else []), rows, self.truncate, 12.5

    def plan_cost(self, sql: str, binds: dict[str, Any] | None = None) -> int | None:
        return None

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        return None


class FakeRegistry:
    def __init__(self, connections: dict[str, FakeConnection]) -> None:
        self._connections = connections

    def get(self, database_name: str) -> FakeConnection:
        from oracle_mcp.errors import DatabaseUnavailableError

        conn = self._connections.get((database_name or "").upper())
        if conn is None:
            raise DatabaseUnavailableError(f"{database_name} is not served here.")
        return conn

    @property
    def names(self) -> list[str]:
        return sorted(self._connections)

    def public_metadata(self) -> list[dict[str, Any]]:
        return [c.profile.public_metadata() for c in self._connections.values()]

    def close_all(self) -> None:
        return None


@pytest.fixture
def onprem_conn() -> FakeConnection:
    return FakeConnection("ONPREM", "On-Prem Oracle DB")


@pytest.fixture
def atp_conn() -> FakeConnection:
    return FakeConnection("ATP", "Oracle ATP")


@pytest.fixture
def registry(onprem_conn: FakeConnection, atp_conn: FakeConnection) -> FakeRegistry:
    return FakeRegistry({"ONPREM": onprem_conn, "ATP": atp_conn})


@pytest.fixture
def settings(tmp_path: Path, policy_dir: Path) -> Settings:
    return Settings(
        profile="both",
        transport="stdio",
        max_rows=500,
        query_timeout_seconds=30,
        role_binding_mode="argument",  # tests exercise multiple roles
        policy_dir=policy_dir,
        audit_sink="file",
        audit_file=tmp_path / "audit.jsonl",
    )


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(sink="file", file_path=tmp_path / "audit.jsonl")


@pytest.fixture
def service(
    settings: Settings, store: PolicyStore, registry: FakeRegistry, audit_logger: AuditLogger
) -> ToolService:
    return ToolService(
        settings=settings, store=store, registry=registry, audit=audit_logger
    )


@pytest.fixture
def oracle_profile() -> OracleProfile:
    return OracleProfile(
        profile="onprem",
        database_name="ONPREM",
        display_name="On-Prem Oracle DB",
        user="CHATBOT_RO",
        password="super-secret-password",  # noqa: S106 - fixture value
        host="db.internal",
        port=1521,
        service_name="CDMPRD",
    )
