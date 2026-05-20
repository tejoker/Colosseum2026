-- S12 — security audit log.
--
-- Append-only trail of security-relevant events: auth failures, signature
-- mismatches, cross-tenant attempts, policy violations, admin-key rotations,
-- rate-limit trips. The core writes here from middleware/audit_log.rs;
-- operators query it via GET /v1/admin/audit (admin-gated, tenant-scoped)
-- or ship the dedicated `sauron::audit::security` tracing target to a SIEM.
--
-- Idempotent: every statement uses IF NOT EXISTS so the migration is a
-- no-op when re-applied. No data migration is needed — this is a brand-new
-- table introduced in S12 for pentest readiness.

BEGIN;

CREATE TABLE IF NOT EXISTS security_audit_log (
    audit_id    TEXT    PRIMARY KEY,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    event_type  TEXT    NOT NULL,
    event_json  TEXT    NOT NULL,
    timestamp   BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_ts
    ON security_audit_log(tenant_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_security_audit_type_ts
    ON security_audit_log(event_type, timestamp);

COMMIT;
