# =============================================================================
# Oracle MCP chatbot server
# =============================================================================
# Thin-mode python-oracledb, so no Oracle Instant Client is needed and the image
# stays small. If you require thick mode, see the commented stage at the bottom.
# =============================================================================

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Dependencies first so application edits do not invalidate the layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

# Non-root, no shell, no home directory to write into.
RUN groupadd --system --gid 10001 mcp \
 && useradd --system --uid 10001 --gid mcp --no-create-home --shell /usr/sbin/nologin mcp \
 && mkdir -p /app/logs /opt/oracle/wallets \
 && chown -R mcp:mcp /app/logs \
 && chmod 555 /app/src /app/config

USER mcp

# Wallets are mounted read-only at runtime, never baked into the image:
#   -v /secure/host/path/atp-wallet:/opt/oracle/wallets/atp:ro
VOLUME ["/app/logs"]

ENV ORACLE_MCP_PROFILE=onprem \
    ORACLE_MCP_TRANSPORT=http \
    ORACLE_MCP_HTTP_HOST=0.0.0.0 \
    ORACLE_MCP_HTTP_PORT=8080 \
    ORACLE_MCP_POLICY_DIR=/app/config/policy \
    ORACLE_MCP_AUDIT_FILE=/app/logs/audit.jsonl \
    ORACLE_MCP_ROLE_BINDING_MODE=env

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=20s --start-period=20s --retries=3 \
  CMD ["python", "-m", "oracle_mcp.server", "--check"]

ENTRYPOINT ["python", "-m", "oracle_mcp.server"]

# =============================================================================
# Thick mode variant
# =============================================================================
# Only needed for features thin mode does not cover (certain legacy auth
# mechanisms, Advanced Queuing, some national character set handling).
#
# FROM base AS thick
# USER root
# RUN apt-get update \
#  && apt-get install -y --no-install-recommends libaio1 unzip curl \
#  && mkdir -p /opt/oracle \
#  && curl -Lo /tmp/ic.zip https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
#  && unzip -q /tmp/ic.zip -d /opt/oracle && rm /tmp/ic.zip \
#  && rm -rf /var/lib/apt/lists/*
# ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_23_5 \
#     ONPREM_MODE=thick \
#     ONPREM_LIB_DIR=/opt/oracle/instantclient_23_5
# USER mcp
