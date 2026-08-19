-- =============================================================================
-- Oracle ATP: least-privilege chatbot account
-- =============================================================================
-- Run as ADMIN on the Autonomous Database. ATP differs from on-prem in two ways
-- that matter here: consumer groups replace most resource-limit tuning, and the
-- ADMIN account must never be used by the application.
-- =============================================================================

-- 1. The account.
CREATE USER chatbot_ro IDENTIFIED BY "&chatbot_password";

GRANT CREATE SESSION TO chatbot_ro;

-- 2. Pin the account to the LOW consumer group.
--    LOW gives the smallest share of CPU and, critically, no parallelism, so
--    chatbot traffic cannot degrade production workloads. Connect with the
--    matching _low TNS alias as well; both must agree.
BEGIN
  CONS_RESOURCE_MANAGER.SET_CONSUMER_GROUP_MAPPING(
    attribute      => DBMS_RESOURCE_MANAGER.ORACLE_USER,
    value          => 'CHATBOT_RO',
    consumer_group => 'LOW');
END;
/

-- 3. Object grants: allowlisted objects only.
GRANT SELECT ON atp_rpt.v_customer_master  TO chatbot_ro;
GRANT SELECT ON atp_rpt.v_customer_account TO chatbot_ro;
GRANT SELECT ON atp_ops.v_load_rejects     TO chatbot_ro;
GRANT SELECT ON atp_cdm.customer           TO chatbot_ro;

-- 4. Explicitly withhold the ATP-specific escape hatches.
--    ATP grants DWROLE broadly by default; do not grant it here.
-- REVOKE DWROLE FROM chatbot_ro;

-- Never grant to this account on ATP:
--   DWROLE                    - bundles create/write privileges
--   EXECUTE ON DBMS_CLOUD     - object storage read/write; an exfiltration path
--   EXECUTE ON DBMS_NETWORK_ACL_ADMIN
--   EXECUTE ON UTL_HTTP / UTL_SMTP / UTL_TCP
--   ALTER SYSTEM / ALTER SESSION beyond defaults

-- 5. Restrict which networks may use this account (ATP supports this natively).
--    Combine with a private endpoint or an ACL on the ADB itself.
-- BEGIN
--   DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(...);
-- END;
-- /

-- 6. Verify.
-- SELECT privilege FROM user_sys_privs;
-- SELECT owner, table_name, privilege FROM user_tab_privs_recd;
-- SELECT granted_role FROM user_role_privs;
