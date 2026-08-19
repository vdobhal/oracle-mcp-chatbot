"""Error taxonomy.

Every failure surfaced to the LLM is a stable machine code plus a message that
is safe to show a business user. Oracle's own error text is deliberately not
propagated: ORA- messages routinely echo SQL fragments, object names and bind
values, which would leak schema structure and data through the model.
"""

from __future__ import annotations

from typing import Any


class ChatbotError(Exception):
    """Base class. Carries a stable code plus user-safe remediation text."""

    code = "INTERNAL_ERROR"
    user_message = "The request could not be completed."

    def __init__(
        self,
        detail: str | None = None,
        *,
        next_steps: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or self.user_message)
        self.detail = detail
        self.next_steps = next_steps or []
        self.context = context or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "ERROR",
            "error_code": self.code,
            "message": self.detail or self.user_message,
            "next_steps": self.next_steps,
            **({"context": self.context} if self.context else {}),
        }


class ConfigurationError(ChatbotError):
    code = "CONFIGURATION_ERROR"
    user_message = "The server is not configured correctly."


class UnknownDatabaseError(ChatbotError):
    code = "UNKNOWN_DATABASE"
    user_message = "That database is not served by this MCP server."


class UnknownRoleError(ChatbotError):
    code = "UNKNOWN_ROLE"
    user_message = "The requested role is not defined in the access control model."


class AccessDeniedError(ChatbotError):
    code = "ACCESS_DENIED"
    user_message = "Your role is not authorised to access that data."


class ObjectNotAllowlistedError(ChatbotError):
    code = "OBJECT_NOT_ALLOWLISTED"
    user_message = "That schema, table or view is not approved for chatbot access."


class MetadataUnavailableError(ChatbotError):
    code = "METADATA_UNAVAILABLE"
    user_message = "Metadata for that object is not available."


class SqlValidationError(ChatbotError):
    code = "SQL_VALIDATION_FAILED"
    user_message = "The SQL failed safety validation and was not executed."


class QueryTimeoutError(ChatbotError):
    code = "QUERY_TIMEOUT"
    user_message = "The query exceeded the allowed execution time and was cancelled."


class DatabaseUnavailableError(ChatbotError):
    code = "DATABASE_UNAVAILABLE"
    user_message = "The database could not be reached."


class QueryExecutionError(ChatbotError):
    code = "QUERY_EXECUTION_FAILED"
    user_message = "The database rejected the query."
