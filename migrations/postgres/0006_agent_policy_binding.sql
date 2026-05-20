-- S10 — server-side agent → policy binding registry.
--
-- Replaces the dashboard's localStorage-only binding with a tenant-scoped
-- table the core can read. One row per (tenant_id, agent_id); UPSERTs are
-- last-write-wins. The secondary index supports reverse lookups
-- ("which agents are bound to policy X?") for tenant-scoped audit views.
--
-- Idempotent: every statement uses IF NOT EXISTS so the migration is a
-- no-op when re-applied. No data migration is needed — pre-S10 bindings
-- only lived in browser localStorage and are not authoritative.

BEGIN;

CREATE TABLE IF NOT EXISTS agent_policy_bindings (
    tenant_id  TEXT    NOT NULL DEFAULT 'default',
    agent_id   TEXT    NOT NULL,
    policy_id  TEXT    NOT NULL,
    bound_at   BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_policy_bindings_policy
    ON agent_policy_bindings(tenant_id, policy_id);

COMMIT;
