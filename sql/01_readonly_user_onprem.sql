-- =============================================================================
-- On-Prem Oracle DB: least-privilege chatbot account
-- =============================================================================
-- Run as a DBA. This is the first of the three access layers; the account is
-- granted only what the allowlist in config/policy/onprem.yaml declares, so a
-- bug in the application cannot reach anything the DBA did not approve.
--
-- Substitute a real password from your secret manager for &chatbot_password.
-- =============================================================================

-- 1. A dedicated profile: caps sessions and forces password rotation.
CREATE PROFILE chatbot_ro_profile LIMIT
  SESSIONS_PER_USER          5
  CPU_PER_CALL               3000        -- 30 seconds, in hundredths of a second
  LOGICAL_READS_PER_CALL     1000000     -- kills runaway full scans
  IDLE_TIME                  15
  CONNECT_TIME               240
  FAILED_LOGIN_ATTEMPTS      5
  PASSWORD_LIFE_TIME         90
  PASSWORD_REUSE_MAX         12
  PASSWORD_GRACE_TIME        7;

-- 2. The account. No default tablespace quota: it can never create a segment.
CREATE USER chatbot_ro
  IDENTIFIED BY "&chatbot_password"
  DEFAULT TABLESPACE users
  TEMPORARY TABLESPACE temp
  QUOTA 0 ON users
  PROFILE chatbot_ro_profile
  ACCOUNT UNLOCK;

-- 3. Session access only. CREATE SESSION is the sole system privilege granted.
GRANT CREATE SESSION TO chatbot_ro;

-- Deliberately NOT granted, and each for a reason:
--   CONNECT / RESOURCE   - role creep; CONNECT has carried extra privileges historically
--   SELECT ANY TABLE     - defeats the entire allowlist model
--   CREATE ANY ...       - write capability of any kind
--   CREATE PROCEDURE     - stored code is a persistence mechanism
--   UNLIMITED TABLESPACE - allows segment creation
--   EXECUTE on DBMS_*    - network, file and dynamic SQL escape hatches

-- 4. Object grants: only the objects in the allowlist, and only SELECT.
GRANT SELECT ON cdm_rpt.v_customer_master   TO chatbot_ro;
GRANT SELECT ON cdm_rpt.v_customer_hierarchy TO chatbot_ro;
GRANT SELECT ON cdm_rpt.v_ea_contract       TO chatbot_ro;
GRANT SELECT ON cdm_ops.v_integration_status TO chatbot_ro;

-- Base tables are granted only if analyst/architect roles genuinely need them.
-- Prefer exposing a curated view instead.
GRANT SELECT ON cdm.customer TO chatbot_ro;

-- 5. Optional: a VPD policy pinning the account to read-only at the row source.
--    Belt and braces alongside SET TRANSACTION READ ONLY in the application.
-- BEGIN
--   DBMS_RLS.ADD_POLICY(
--     object_schema   => 'CDM',
--     object_name     => 'CUSTOMER',
--     policy_name     => 'CHATBOT_RO_NO_WRITE',
--     policy_function => 'CDM.CHATBOT_RO_PREDICATE',
--     statement_types => 'INSERT,UPDATE,DELETE');
-- END;
-- /

-- 6. Verify the account holds nothing unexpected. Both queries should return
--    only what is listed above.
-- SELECT privilege FROM dba_sys_privs WHERE grantee = 'CHATBOT_RO';
-- SELECT owner, table_name, privilege FROM dba_tab_privs WHERE grantee = 'CHATBOT_RO';
-- SELECT granted_role FROM dba_role_privs WHERE grantee = 'CHATBOT_RO';
