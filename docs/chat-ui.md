# Standalone chat UI (not Cursor)

The chatbot is an MCP server. Cursor is one client. This UI is another: a
browser app that calls the **same** `ToolService` (schemas, tables, metadata,
search, validate, execute, explain, compare) without Cursor.

## Run it

From the project root, with `.env` already able to reach On-Prem and/or ATP:

```bash
cd oracle-mcp-chatbot
export PYTHONPATH=.pydeps:src

pip install --target .pydeps fastapi uvicorn   # once

# Set an LLM key in .env (OpenAI or any OpenAI-compatible gateway).
# Paste the real key -- a literal placeholder is rejected at startup.
# ORACLE_MCP_LLM_API_KEY=sk-your-real-key
# ORACLE_MCP_LLM_BASE_URL=https://api.openai.com/v1
# ORACLE_MCP_LLM_MODEL=gpt-4o

python3 -m oracle_mcp.chat --profile both
```

Open **http://127.0.0.1:8500**.

`--profile both` is what you want for a customer UI that can ask about On-Prem
IB **and** ATP customer/GTC data. `--profile onprem` or `atp` restricts it to
one database. Role is still `ORACLE_MCP_PINNED_ROLE` from `.env`; the browser
cannot change it.

## What is attached

| UI / API | Capability |
|---|---|
| Chat box | Natural-language questions → metadata discovery → `validate_sql` → `execute_readonly_sql` |
| Sidebar | Live DB ping, pinned role, tool list |
| Starter prompts | The same questions used in operator testing |
| `/api/health` | Databases, tools, whether an LLM key is configured |
| `/api/chat` | `{ "message": "...", "history": [...] }` |

SQL never runs unless it passes the same guardrails as the MCP server. Tool
activity is shown as chips under each answer (which tools fired).

## LLM

The UI process does not contain a model. It calls an OpenAI-compatible
`/chat/completions` endpoint. If `ORACLE_MCP_LLM_API_KEY` is empty *or is still a
template placeholder such as `...`*, the page still loads and health works, but
sending a message returns HTTP 503 explaining which of the two it is. `GET
/api/health` reports the same under `llm_detail`, along with `env_files_checked`
so you can confirm which `.env` was read.

`.env` is located relative to the repository root, not the working directory, so
starting the server from a parent folder still picks up credentials.

A private gateway is fine: set `ORACLE_MCP_LLM_BASE_URL` to its base (or to the
full `.../chat/completions` URL).

## What this is not

It is still a **single pinned identity** per process (the same model as the MCP
servers). Putting it on a shared URL without a login in front would let every
visitor act as `ORACLE_MCP_PINNED_USER_ID`. Bind to loopback, or put it behind
your own SSO, before anyone else uses it.

Credentials stay on the server. The browser never receives DSN, passwords, or
wallets.
