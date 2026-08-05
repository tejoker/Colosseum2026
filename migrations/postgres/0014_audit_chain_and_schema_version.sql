BEGIN;

ALTER TABLE security_audit_log ADD COLUMN IF NOT EXISTS seq BIGINT;
ALTER TABLE security_audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE security_audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_security_audit_seq
    ON security_audit_log(seq) WHERE seq IS NOT NULL;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    applied_at BIGINT NOT NULL
);
INSERT INTO schema_migrations(version, applied_at)
VALUES (14, EXTRACT(EPOCH FROM NOW())::BIGINT)
ON CONFLICT (version) DO NOTHING;

COMMIT;
