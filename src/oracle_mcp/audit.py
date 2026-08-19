"""Audit logging.

Every tool invocation produces one record whether it succeeded, was rejected by
the guardrails, or failed in the database. Rejections matter most: a run of
``SQL_VALIDATION_FAILED`` events from one user is what an attempted bypass looks
like from the outside.

Two properties the writer guarantees:

* SQL is stored with literals replaced by ``?``, plus a SHA-256 of the exact
  text that ran. That gives forensics an exact match without copying the values
  the masking layer just suppressed into a second store.
* Audit failures never propagate. A full disk must not take the chatbot down,
  so write errors are logged and swallowed.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .sql_guard import fingerprint, redact_sql_literals

logger = logging.getLogger(__name__)

MAX_QUESTION_CHARS = 2000


def new_request_id() -> str:
    return uuid.uuid4().hex


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sanitize_free_text(text: str | None, limit: int = MAX_QUESTION_CHARS) -> str:
    """Neutralise a user-supplied string before it is stored or echoed back.

    Newlines are collapsed so an injected ``\\nIgnore previous instructions``
    cannot appear as its own line when the audit trail is later reviewed in a
    model-assisted tool.
    """
    if not text:
        return ""
    flattened = " ".join(str(text).split())
    return flattened[:limit] + ("...[truncated]" if len(flattened) > limit else "")


@dataclass
class AuditEvent:
    request_id: str
    event_time: str
    tool_name: str
    database_name: str
    user_id: str
    user_role: str
    status: str
    user_question: str = ""
    sql_redacted: str = ""
    sql_sha256: str = ""
    validation_status: str = ""
    validation_errors: list[str] = field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    execution_ms: float = 0.0
    masked_columns: list[str] = field(default_factory=list)
    referenced_objects: list[str] = field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    response_summary: str = ""
    client_host: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Writes audit events to a JSONL file, an Oracle table, or both."""

    def __init__(
        self,
        *,
        sink: str,
        file_path: Path,
        table_name: str = "",
        connection: Any = None,
    ) -> None:
        self.sink = sink
        self.file_path = Path(file_path)
        self.table_name = table_name
        self.connection = connection
        self._lock = threading.Lock()
        if self._writes_file:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def _writes_file(self) -> bool:
        return self.sink in {"file", "both"}

    @property
    def _writes_db(self) -> bool:
        return self.sink in {"db", "both"} and self.connection is not None

    def record(self, event: AuditEvent) -> None:
        if self.sink == "none":
            return
        payload = event.as_dict()
        if self._writes_file:
            self._write_file(payload)
        if self._writes_db:
            self._write_db(event)

    def _write_file(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False, default=str)
        try:
            with self._lock:
                # Opened per write and flushed so an abrupt shutdown cannot lose
                # the record of the request that caused it.
                with self.file_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as exc:
            logger.error("Audit file write failed (%s): %s", self.file_path, exc)

    def _write_db(self, event: AuditEvent) -> None:
        sql = f"""
            INSERT INTO {self.table_name} (
                request_id, event_time, tool_name, database_name, user_id, user_role,
                status, user_question, sql_redacted, sql_sha256, validation_status,
                validation_errors, row_count, truncated, execution_ms, masked_columns,
                referenced_objects, error_code, error_message, response_summary
            ) VALUES (
                :request_id, SYSTIMESTAMP, :tool_name, :database_name, :user_id, :user_role,
                :status, :user_question, :sql_redacted, :sql_sha256, :validation_status,
                :validation_errors, :row_count, :truncated, :execution_ms, :masked_columns,
                :referenced_objects, :error_code, :error_message, :response_summary
            )
        """
        binds = {
            "request_id": event.request_id,
            "tool_name": event.tool_name,
            "database_name": event.database_name,
            "user_id": event.user_id,
            "user_role": event.user_role,
            "status": event.status,
            "user_question": event.user_question[:4000],
            "sql_redacted": event.sql_redacted[:4000],
            "sql_sha256": event.sql_sha256,
            "validation_status": event.validation_status,
            "validation_errors": json.dumps(event.validation_errors)[:4000],
            "row_count": event.row_count,
            "truncated": "Y" if event.truncated else "N",
            "execution_ms": round(event.execution_ms, 2),
            "masked_columns": json.dumps(event.masked_columns)[:4000],
            "referenced_objects": json.dumps(event.referenced_objects)[:4000],
            "error_code": event.error_code[:100],
            "error_message": event.error_message[:2000],
            "response_summary": event.response_summary[:4000],
        }
        try:
            # The audit writer is the one place that intentionally holds a
            # read-write connection, so it bypasses read_only_cursor().
            pool = self.connection._pool_or_create()  # noqa: SLF001
            conn = pool.acquire()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(sql, binds)
                conn.commit()
            finally:
                pool.release(conn)
        except Exception as exc:  # noqa: BLE001 - audit must never break the request
            logger.error("Audit DB write failed: %s", type(exc).__name__)


def build_event(
    *,
    request_id: str,
    tool_name: str,
    database_name: str,
    user_id: str,
    user_role: str,
    status: str,
    user_question: str = "",
    sql: str = "",
    **extra: Any,
) -> AuditEvent:
    return AuditEvent(
        request_id=request_id or new_request_id(),
        event_time=_utc_now(),
        tool_name=tool_name,
        database_name=database_name,
        user_id=user_id,
        user_role=user_role,
        status=status,
        user_question=sanitize_free_text(user_question),
        sql_redacted=redact_sql_literals(sql) if sql else "",
        sql_sha256=fingerprint(sql) if sql else "",
        **extra,
    )
