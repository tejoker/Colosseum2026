-- Sprint 7 — customer-side stat aggregation + ZK integrity.
--
-- Holds the per-tenant per-period claimed metric values that customers POST to
-- /v1/stats/submit, together with the ZK proof binding the claim to a
-- Merkle-committed receipt set. The cross-tenant cohort view (Sprint 8 DP
-- publish, Sprint 9 dashboard) reads from this table.
--
-- The (tenant_id, agent_id, metric_id, period_start) primary key encodes
-- idempotency: same submission landing twice via network retry or scheduler
-- restart overwrites in place via ON CONFLICT. agent_id = '' marks tenant-
-- aggregate rollups; per-agent submissions use the agent identifier.

BEGIN;

CREATE TABLE IF NOT EXISTS customer_stats (
    tenant_id     TEXT    NOT NULL DEFAULT 'default',
    agent_id      TEXT    NOT NULL DEFAULT '',
    metric_id     TEXT    NOT NULL,
    claimed_value BIGINT  NOT NULL,
    n_records     BIGINT  NOT NULL,
    period_start  BIGINT  NOT NULL,
    period_end    BIGINT  NOT NULL,
    merkle_root   TEXT    NOT NULL,
    proof_b64     TEXT    NOT NULL,
    vk_id         TEXT    NOT NULL,
    submitted_at  BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, metric_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_customer_stats_tenant_period
    ON customer_stats(tenant_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_customer_stats_metric_period
    ON customer_stats(metric_id, period_start, period_end);

COMMIT;
