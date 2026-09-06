#!/usr/bin/env bash
# Start the Standalone Oracle MCP & Collibra Chatbot Web UI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

export PYTHONPATH="${PROJECT_ROOT}/.pydeps:${PROJECT_ROOT}/src:${PYTHONPATH}"

PORT="${CHAT_UI_PORT:-8090}"
HOST="${CHAT_UI_HOST:-127.0.0.1}"

echo "Starting MDM (CDM,IB, Collibra) Data Assistant Web UI on http://${HOST}:${PORT}..."
exec python3 -m uvicorn oracle_mcp.webapp:app --host "${HOST}" --port "${PORT}" --reload
