"""Standalone chat UI — not Cursor.

    PYTHONPATH=.pydeps:src python3 -m oracle_mcp.webapp --profile both

Binds to loopback by default. The language model is configured with CHAT_LLM_*
variables; Oracle credentials stay in the existing ONPREM_* / ATP_* settings.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import ChatAgent, ChatLlm, LlmError, iter_sse, tools_for
from .collibra import CollibraClient, DEFAULT_COLLIBRA_URL
from .server import build_service, configure_logging
from .settings import Settings, get_settings

logger = logging.getLogger("oracle_mcp.web")

STATIC_DIR = Path(__file__).resolve().parents[2] / "web" / "static"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def collibra_from_env() -> CollibraClient | None:
    raw_enabled = _env("COLLIBRA_MCP_ENABLED")
    url = _env("COLLIBRA_MCP_URL", DEFAULT_COLLIBRA_URL)
    api_key = _env("COLLIBRA_MCP_API_KEY") or _env("CHAT_LLM_API_KEY")

    enabled = False
    if raw_enabled:
        enabled = raw_enabled.lower() in {"1", "true", "yes", "on"}
    elif url and api_key:
        enabled = True

    if not enabled or not url:
        return None

    timeout = 30.0
    raw_timeout = _env("COLLIBRA_MCP_TIMEOUT_SECONDS")
    if raw_timeout:
        try:
            timeout = float(raw_timeout)
        except ValueError:
            pass

    return CollibraClient(url=url, api_key=api_key, timeout_seconds=timeout)


def llm_from_env() -> ChatLlm | None:
    api_key = _env("CHAT_LLM_API_KEY")
    model = _env("CHAT_LLM_MODEL")
    if not api_key or not model:
        return None
    kind = _env("CHAT_LLM_KIND", "openai") or "openai"
    default_base = (
        "https://api.openai.com/v1" if kind != "azure" else _env("CHAT_LLM_BASE_URL")
    )
    base = _env("CHAT_LLM_BASE_URL", default_base)
    if kind == "azure" and not base:
        return None
    return ChatLlm(
        base_url=base,
        api_key=api_key,
        model=model,
        kind=kind,
        azure_api_version=_env("CHAT_LLM_AZURE_API_VERSION", "2024-10-21") or "2024-10-21",
    )


class ChatTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    history: list[ChatTurn] = Field(default_factory=list)


def create_app(
    settings: Settings | None = None,
    service=None,
    agent: ChatAgent | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    service = service or build_service(settings)
    agent = agent or ChatAgent(service, llm_from_env(), collibra=collibra_from_env())
    app = FastAPI(title="Oracle data assistant", docs_url=None, redoc_url=None)
    app.state.service = service
    app.state.agent = agent
    app.state.settings = settings

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        databases = []
        for name in service.registry.names:
            try:
                ok = service.registry.get(name).ping()
            except Exception:
                ok = False
            databases.append({"name": name, "ok": ok})
        return {
            "ok": True,
            "llm_configured": agent.llm is not None,
            "collibra_configured": agent.collibra is not None,
            "profile": settings.profile,
            "role": settings.pinned_role,
            "databases": databases,
            "reconciliation": settings.reconciliation_enabled,
            "tools": [t["function"]["name"] for t in tools_for(service, agent.collibra)],
        }

    @app.get("/api/session")
    def session() -> dict[str, Any]:
        role = service.store.role(settings.pinned_role)
        suggestions = [
            "What customer information is available in ATP?",
            "Show me all party roles.",
            "How many systems are decommissioned?",
            "Company, NAGP and GTC attributes for address CMAT ID 21757805.",
            "Count install-base serials by product series.",
        ]
        if agent.collibra is not None:
            suggestions.append("Check Collibra for IB Attributes domain location and assets.")
        return {
            "role": role.name,
            "clearance": role.clearance,
            "show_sql": role.show_sql,
            "user_id": settings.pinned_user_id,
            "llm_configured": agent.llm is not None,
            "collibra_configured": agent.collibra is not None,
            "databases": service.registry.public_metadata(),
            "suggestions": suggestions,
        }

    @app.post("/api/chat")
    def chat(body: ChatRequest) -> dict[str, Any]:
        history = [t.model_dump() for t in body.history[-20:]]
        try:
            return agent.run(body.question, history)
        except LlmError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/api/chat/stream")
    def chat_stream(body: ChatRequest) -> StreamingResponse:
        history = [t.model_dump() for t in body.history[-20:]]

        def events():
            queue: list[dict[str, Any]] = []

            def on_event(event: dict[str, Any]) -> None:
                queue.append(event)

            try:
                result = agent.run(body.question, history, on_event=on_event)
                queue.append({"type": "done", "tools": result.get("tools") or []})
            except LlmError as exc:
                queue.append({"type": "error", "message": str(exc)})
            yield from iter_sse(iter(queue))

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.get("/")
    def index() -> FileResponse:
        index = STATIC_DIR / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=500, detail="Chat UI files are missing.")
        return FileResponse(index)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Oracle data assistant chat UI")
    parser.add_argument("--profile", choices=["onprem", "atp", "both"])
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    settings = get_settings()
    updates: dict[str, Any] = {"transport": "http"}
    if args.profile:
        updates["profile"] = args.profile
    settings = settings.model_copy(update=updates)
    configure_logging(settings.log_level)

    host = args.host or _env("CHAT_UI_HOST") or "127.0.0.1"
    port = args.port or int(_env("CHAT_UI_PORT") or "8090")
    if agent_warning := (None if llm_from_env() else "CHAT_LLM_API_KEY / CHAT_LLM_MODEL not set"):
        logger.warning("%s — the UI will start, but chat will return HTTP 503 until they are.", agent_warning)

    import uvicorn

    app = create_app(settings)
    logger.info("Chat UI on http://%s:%s  profile=%s", host, port, settings.profile)
    uvicorn.run(app, host=host, port=port, log_level=settings.log_level.lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
