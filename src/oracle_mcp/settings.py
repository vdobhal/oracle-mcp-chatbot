"""Configuration.

Credentials are held as ``SecretStr`` so that logging a settings object, a
traceback frame, or a ``repr()`` never renders a password or wallet passphrase.
Call ``.get_secret_value()`` only at the point of connecting.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigurationError

ProfileName = Literal["onprem", "atp"]
DB_NAME_BY_PROFILE = {"onprem": "ONPREM", "atp": "ATP"}
PROFILE_BY_DB_NAME = {v: k for k, v in DB_NAME_BY_PROFILE.items()}

# Anchored to the repository, not the working directory. An editor or launcher
# that starts the process from the workspace root would otherwise find no .env,
# and the server would come up with no credentials and no LLM key while looking
# perfectly healthy.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
_loaded_env_files: set[str] = set()

# Values that are syntactically present but obviously not real. Treating these
# as configured produces a confusing failure at first use rather than a clear
# one at startup.
_PLACEHOLDER_SECRETS = frozenset(
    {
        "",
        "...",
        "change-me",
        "changeme",
        "your-api-key",
        "your-key-here",
        "sk-xxx",
        "xxx",
        "todo",
        "none",
        "null",
    }
)


def is_placeholder(value: str) -> bool:
    return value.strip().lower() in _PLACEHOLDER_SECRETS


def env_file_candidates() -> list[Path]:
    """The ``.env`` files consulted, in precedence order.

    A file in the current directory wins over the repository one so a per-shell
    override still works, but neither is required to be the working directory.
    """
    candidates = [Path.cwd() / DEFAULT_ENV_FILE.name, DEFAULT_ENV_FILE]
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def load_env_file(path: str | Path | None = None) -> None:
    """Merge ``.env`` into ``os.environ``.

    ``BaseSettings`` reads its own ``ORACLE_MCP_*`` fields from the env file, but
    the per-database ``ONPREM_*`` / ``ATP_*`` variables are read straight from
    the environment. Without this, credentials placed in ``.env`` would be
    silently ignored and the server would report a missing username.

    Real environment variables always win, so secrets injected by a container
    runtime or vault agent override a file left on disk.
    """
    targets = [Path(path)] if path is not None else env_file_candidates()
    for target in targets:
        resolved = str(target.resolve()) if target.exists() else str(target)
        if resolved in _loaded_env_files or not target.is_file():
            continue
        for key, value in dotenv_values(target).items():
            if value is not None and key not in os.environ:
                os.environ[key] = value
        _loaded_env_files.add(resolved)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    try:
        return int(raw) if raw else default
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be an integer, got {raw!r}") from exc


class OracleProfile(BaseModel):
    """Connection settings for one named Oracle database."""

    profile: ProfileName
    database_name: str
    display_name: str
    enabled: bool = True

    user: str = ""
    password: SecretStr = SecretStr("")

    host: str = ""
    port: int = 1521
    service_name: str = ""
    dsn: str = ""

    mode: Literal["thin", "thick"] = "thin"
    lib_dir: str = ""

    wallet_dir: str = ""
    wallet_password: SecretStr = SecretStr("")
    config_dir: str = ""

    pool_min: int = 1
    pool_max: int = 4
    pool_increment: int = 1

    policy_file: str = ""

    @model_validator(mode="after")
    def _check(self) -> OracleProfile:
        if not self.enabled:
            return self
        if not self.user:
            raise ValueError(f"{self.profile.upper()}_USER is required")
        if not self.password.get_secret_value():
            raise ValueError(f"{self.profile.upper()}_PASSWORD is required")
        if not self.effective_dsn:
            raise ValueError(
                f"{self.profile.upper()} needs either a DSN or HOST+PORT+SERVICE_NAME"
            )
        if self.mode == "thick" and self.wallet_password.get_secret_value():
            # cwallet.sso is passwordless by design; a wallet password here means
            # the operator unpacked the wrong artefact for thick mode.
            raise ValueError(
                f"{self.profile.upper()}_WALLET_PASSWORD is not used in thick mode; "
                "thick mode reads cwallet.sso instead"
            )
        return self

    @property
    def effective_dsn(self) -> str:
        """Explicit DSN wins; otherwise build an EZConnect string."""
        if self.dsn:
            return self.dsn
        if self.host and self.service_name:
            return f"{self.host}:{self.port}/{self.service_name}"
        return ""

    @property
    def uses_wallet(self) -> bool:
        return bool(self.wallet_dir)

    def connect_kwargs(self) -> dict[str, object]:
        """Arguments for ``oracledb.create_pool``. Secrets are unwrapped here only."""
        kwargs: dict[str, object] = {
            "user": self.user,
            "password": self.password.get_secret_value(),
            "dsn": self.effective_dsn,
            "min": self.pool_min,
            "max": self.pool_max,
            "increment": self.pool_increment,
        }
        config_dir = self.config_dir or self.wallet_dir
        if config_dir:
            kwargs["config_dir"] = config_dir
        if self.wallet_dir:
            # Thin mode reads ewallet.pem (needs the passphrase); thick mode reads
            # cwallet.sso from the same directory and ignores the passphrase.
            kwargs["wallet_location"] = self.wallet_dir
            if self.mode == "thin" and self.wallet_password.get_secret_value():
                kwargs["wallet_password"] = self.wallet_password.get_secret_value()
        return kwargs

    def public_metadata(self) -> dict[str, object]:
        """Connection description with every secret-bearing field removed."""
        return {
            "database_name": self.database_name,
            "display_name": self.display_name,
            "profile": self.profile,
            "driver_mode": self.mode,
            "wallet_configured": self.uses_wallet,
            "tls": "mTLS (wallet)" if self.uses_wallet else "TCP/TLS per DSN",
            "enabled": self.enabled,
        }


def _load_profile(profile: ProfileName) -> OracleProfile:
    p = profile.upper()
    defaults = {
        "onprem": ("On-Prem Oracle DB", "onprem.yaml"),
        "atp": ("Oracle ATP", "atp.yaml"),
    }[profile]
    return OracleProfile(
        profile=profile,
        database_name=DB_NAME_BY_PROFILE[profile],
        display_name=_env(f"{p}_DISPLAY_NAME", defaults[0]),
        enabled=_env_bool(f"{p}_ENABLED", True),
        user=_env(f"{p}_USER"),
        password=SecretStr(_env(f"{p}_PASSWORD")),
        host=_env(f"{p}_HOST"),
        port=_env_int(f"{p}_PORT", 1521),
        service_name=_env(f"{p}_SERVICE_NAME"),
        dsn=_env(f"{p}_DSN"),
        mode=_env(f"{p}_MODE", "thin").lower() or "thin",  # type: ignore[arg-type]
        lib_dir=_env(f"{p}_LIB_DIR"),
        wallet_dir=_env(f"{p}_WALLET_DIR"),
        wallet_password=SecretStr(_env(f"{p}_WALLET_PASSWORD")),
        config_dir=_env(f"{p}_CONFIG_DIR"),
        pool_min=_env_int(f"{p}_POOL_MIN", 1),
        pool_max=_env_int(f"{p}_POOL_MAX", 4),
        pool_increment=_env_int(f"{p}_POOL_INCREMENT", 1),
        policy_file=_env(f"{p}_POLICY_FILE", defaults[1]),
    )


class Settings(BaseSettings):
    """Process-wide settings. Guardrail values here are hard ceilings."""

    model_config = SettingsConfigDict(
        env_prefix="ORACLE_MCP_",
        # Absolute, so the file is found regardless of where the process starts.
        env_file=(str(DEFAULT_ENV_FILE), ".env"),
        extra="ignore",
        case_sensitive=False,
    )

    profile: Literal["onprem", "atp", "both"] = "onprem"
    transport: Literal["stdio", "http"] = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8080

    max_rows: int = Field(default=500, ge=1, le=10_000)
    query_timeout_seconds: int = Field(default=30, ge=1, le=600)
    max_sql_length: int = Field(default=20_000, ge=100)
    allow_cartesian: bool = False
    sample_row_limit: int = Field(default=20, ge=1, le=100)
    # Optional EXPLAIN PLAN pre-flight. 0 disables it. Requires the read-only
    # user to have a PLAN_TABLE available.
    max_plan_cost: int = Field(default=0, ge=0)

    role_binding_mode: Literal["env", "argument"] = "env"
    pinned_role: str = "business_user"
    pinned_user_id: str = "svc_chatbot"

    policy_dir: Path = Path("config/policy")

    audit_sink: Literal["file", "db", "both", "none"] = "file"
    audit_file: Path = Path("logs/audit.jsonl")
    audit_db_profile: ProfileName = "onprem"
    audit_table: str = "CHATBOT_AUDIT.CHATBOT_AUDIT_LOG"
    log_level: str = "INFO"

    # EIM data-quality framework. The governed rule catalog is read from
    # On-Prem; target SQL may run against either database on the "both" profile.
    dq_catalog_database: str = "ONPREM"
    dq_catalog_schema: str = "EIM"
    dq_catalog_table: str = "EIM_DQ_RULES_LOOKUP"
    dq_history_file: Path = Path("logs/dq-history.jsonl")
    dq_max_rules: int = Field(default=200, ge=1, le=1000)

    # Standalone chat UI (python -m oracle_mcp.chat). The LLM is OpenAI-compatible
    # so a corporate gateway works the same as api.openai.com.
    chat_host: str = "127.0.0.1"
    chat_port: int = Field(default=8500, ge=1, le=65535)
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = "gpt-4o"
    llm_timeout_seconds: int = Field(default=120, ge=10, le=600)

    @field_validator("policy_dir", "audit_file", "dq_history_file")
    @classmethod
    def _anchor_to_repository(cls, value: Path) -> Path:
        """Resolve relative paths against the repo, not the working directory.

        Policy and audit locations are shipped with the source tree, so a
        process launched from a parent directory must still find them.
        Absolute paths (deployments, tests) are left untouched.
        """
        return value if value.is_absolute() else PROJECT_ROOT / value

    @property
    def active_profiles(self) -> list[ProfileName]:
        return ["onprem", "atp"] if self.profile == "both" else [self.profile]  # type: ignore[list-item]

    @property
    def oracle_profiles(self) -> dict[ProfileName, OracleProfile]:
        load_env_file()
        return {name: _load_profile(name) for name in self.active_profiles}

    @property
    def reconciliation_enabled(self) -> bool:
        """Cross-database compare needs both pools in one process."""
        return self.profile == "both"

    @property
    def llm_configured(self) -> bool:
        """Whether an LLM key is present and is not a template placeholder."""
        return not is_placeholder(self.llm_api_key.get_secret_value())

    def llm_status(self) -> str:
        """Why the chat endpoint is unavailable, in operator terms."""
        raw = self.llm_api_key.get_secret_value()
        if not raw.strip():
            files = ", ".join(str(p) for p in env_file_candidates())
            return (
                "ORACLE_MCP_LLM_API_KEY is not set. Add it to your .env, then "
                f"restart this process. Looked in: {files}"
            )
        if is_placeholder(raw):
            return (
                "ORACLE_MCP_LLM_API_KEY is still the template placeholder "
                f"{raw.strip()!r}. Replace it with a real key and restart."
            )
        return "ok"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_env_file()
    return Settings()


def reset_settings_cache() -> None:
    """Used by tests that mutate the environment."""
    get_settings.cache_clear()
    _loaded_env_files.clear()
