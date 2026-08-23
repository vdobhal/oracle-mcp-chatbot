"""Standalone customer chat UI.

    PYTHONPATH=.pydeps:src python3 -m oracle_mcp.chat --profile both

Serves a browser UI on ORACLE_MCP_CHAT_HOST:ORACLE_MCP_CHAT_PORT (default
127.0.0.1:8500). The page talks only to this process; Oracle credentials never
leave the server. Role is the pinned env role, same as the MCP servers.
"""

from __future__ import annotations

import argparse
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .agent import ChatAgent
from .server import build_service, configure_logging
from .settings import Settings, env_file_candidates, get_settings

logger = logging.getLogger("oracle_mcp.chat")
_WEB_DIR = Path(__file__).resolve().parent / "web"


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: list[dict[str, str]] = Field(default_factory=list)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    service = build_service(settings)
    llm_ready = settings.llm_configured
    agent = ChatAgent(service, settings) if llm_ready else None

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        service.registry.close_all()

    app = FastAPI(title="Oracle Data Assistant", lifespan=lifespan)
    app.state.service = service
    app.state.settings = settings
    app.state.agent = agent

    @app.get("/")
    def index() -> FileResponse:
        page = _WEB_DIR / "index.html"
        if not page.is_file():
            raise HTTPException(500, "Chat UI is missing.")
        return FileResponse(page)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        databases = []
        for name in service.registry.names:
            try:
                ok = service.registry.get(name).ping()
            except Exception:  # noqa: BLE001
                ok = False
            databases.append({"name": name, "ok": ok})
        return {
            "status": "ok" if databases else "degraded",
            "databases": databases,
            "role": settings.pinned_role,
            "user_id": settings.pinned_user_id,
            "llm_configured": llm_ready,
            "llm_model": settings.llm_model if llm_ready else None,
            "llm_detail": settings.llm_status(),
            "env_files_checked": [str(p) for p in env_file_candidates()],
            "reconciliation": settings.reconciliation_enabled,
            "max_rows": settings.max_rows,
            "tools": (agent.tool_names() if agent else []),
        }

    @app.post("/api/chat")
    def chat(body: ChatRequest) -> dict[str, Any]:
        if agent is None:
            raise HTTPException(503, settings.llm_status())
        try:
            return agent.ask(body.message.strip(), body.history)
        except RuntimeError as exc:
            raise HTTPException(502, str(exc)) from exc

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Oracle chatbot UI")
    parser.add_argument("--profile", choices=["onprem", "atp", "both"])
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args(argv)

    settings = get_settings()
    updates: dict[str, Any] = {}
    if args.profile:
        updates["profile"] = args.profile
    if args.host:
        updates["chat_host"] = args.host
    if args.port:
        updates["chat_port"] = args.port
    if updates:
        settings = settings.model_copy(update=updates)

    configure_logging(settings.log_level)
    if not settings.llm_configured:
        logger.warning("Chat disabled: %s", settings.llm_status())

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit(
            "The chat UI needs fastapi and uvicorn. "
            "Install with: pip install --target .pydeps fastapi uvicorn"
        ) from exc

    logger.info(
        "Chat UI on http://%s:%s  profile=%s  role=%s",
        settings.chat_host,
        settings.chat_port,
        settings.profile,
        settings.pinned_role,
    )
    uvicorn.run(
        create_app(settings),
        host=settings.chat_host,
        port=settings.chat_port,
        log_level=settings.log_level.lower(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
