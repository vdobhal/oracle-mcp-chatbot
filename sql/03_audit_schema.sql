-- =============================================================================
-- Chatbot audit log
-- =============================================================================
-- Owned by a separate schema from the data being queried, so a compromise of the
-- read-only account cannot alter the record of what it did. The chatbot account
-- gets INSERT only: it can write history but never read or amend it.
-- =============================================================================

CREATE USER chatbot_audit IDENTIFIED BY "&audit_password"
  DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;

CREATE TABLE chatbot_audit.chatbot_audit_log (
  audit_id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id         VARCHAR2(64)   NOT NULL,
  event_time         TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
  tool_name          VARCHAR2(64)   NOT NULL,
  database_name      VARCHAR2(32)   NOT NULL,
  user_id            VARCHAR2(128)  NOT NULL,
  user_role          VARCHAR2(64)   NOT NULL,
  status             VARCHAR2(16)   NOT NULL,
  user_question      VARCHAR2(4000),
  -- SQL is stored with literals replaced by '?'. The hash identifies the exact
  -- statement without persisting the values the masking layer suppressed.
  sql_redacted       VARCHAR2(4000),
  sql_sha256         VARCHAR2(64),
  validation_status  VARCHAR2(16),
  validation_errors  VARCHAR2(4000),
  row_count          NUMBER(10)     DEFAULT 0,
  truncated          CHAR(1)        DEFAULT 'N',
  execution_ms       NUMBER(12,2)   DEFAULT 0,
  masked_columns     VARCHAR2(4000),
  referenced_objects VARCHAR2(4000),
  error_code         VARCHAR2(100),
  error_message      VARCHAR2(2000),
  response_summary   VARCHAR2(4000),
  CONSTRAINT chk_audit_status    CHECK (status IN ('SUCCESS','REJECTED','ERROR')),
  CONSTRAINT chk_audit_truncated CHECK (truncated IN ('Y','N'))
);

COMMENT ON TABLE chatbot_audit.chatbot_audit_log IS
  'Immutable activity log for the Oracle MCP chatbot. One row per tool invocation.';

CREATE INDEX chatbot_audit.ix_audit_time    ON chatbot_audit.chatbot_audit_log (event_time);
CREATE INDEX chatbot_audit.ix_audit_user    ON chatbot_audit.chatbot_audit_log (user_id, event_time);
CREATE INDEX chatbot_audit.ix_audit_status  ON chatbot_audit.chatbot_audit_log (status, event_time);
CREATE INDEX chatbot_audit.ix_audit_request ON chatbot_audit.chatbot_audit_log (request_id);

-- Append-only for the chatbot: no SELECT, no UPDATE, no DELETE.
GRANT INSERT ON chatbot_audit.chatbot_audit_log TO chatbot_ro;

-- Read access for the security and governance teams.
-- GRANT SELECT ON chatbot_audit.chatbot_audit_log TO security_analyst_role;

-- Block amendment even by the owning schema.
CREATE OR REPLACE TRIGGER chatbot_audit.trg_audit_immutable
  BEFORE UPDATE OR DELETE ON chatbot_audit.chatbot_audit_log
BEGIN
  RAISE_APPLICATION_ERROR(-20001, 'Chatbot audit records are immutable.');
END;
/

-- =============================================================================
-- Monitoring queries
-- =============================================================================

-- Repeated guardrail rejections from one user: the signature of a bypass attempt.
-- SELECT user_id, COUNT(*) AS rejections, MIN(event_time), MAX(event_time)
--   FROM chatbot_audit.chatbot_audit_log
--  WHERE status = 'REJECTED' AND event_time > SYSTIMESTAMP - INTERVAL '1' HOUR
--  GROUP BY user_id HAVING COUNT(*) >= 5 ORDER BY rejections DESC;

-- Which approved objects are actually being used.
-- SELECT referenced_objects, COUNT(*) AS uses
--   FROM chatbot_audit.chatbot_audit_log
--  WHERE status = 'SUCCESS' AND event_time > SYSTIMESTAMP - INTERVAL '7' DAY
--  GROUP BY referenced_objects ORDER BY uses DESC;

-- Slowest statements, for tuning or for tightening the timeout.
-- SELECT sql_sha256, sql_redacted, MAX(execution_ms) AS worst_ms, COUNT(*) AS runs
--   FROM chatbot_audit.chatbot_audit_log
--  WHERE status = 'SUCCESS' GROUP BY sql_sha256, sql_redacted
--  ORDER BY worst_ms DESC FETCH FIRST 20 ROWS ONLY;

-- Masking activity, to confirm sensitive columns are being protected in practice.
-- SELECT user_role, masked_columns, COUNT(*) AS occurrences
--   FROM chatbot_audit.chatbot_audit_log
--  WHERE masked_columns IS NOT NULL AND masked_columns != '[]'
--  GROUP BY user_role, masked_columns ORDER BY occurrences DESC;
