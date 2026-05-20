-- SauronID Postgres schema, version 3 — server-side spend ledger.
--
-- Closes the documented gap "Local budget can be tampered" (redteam A3).
-- The SDK's in-memory BudgetTracker flushes periodically into `spend_log`
-- and the running total per (policy_id, agent_id, period_start) lives in
-- `spend_ledger`. POST /v1/policy/evaluate now looks up the authoritative
-- spend total from this ledger instead of trusting the client-supplied
-- `context_overrides.spend_total_usd` (which is now only honoured when
-- the request omits `agent_id`, i.e. simulator mode).
--
-- SQLite ships the equivalent tables via `core/src/db.rs::init_schema`.
--
-- Apply via: sqlx migrate run --source migrations/postgres
--   or:      psql "$DATABASE_URL" -f migrations/postgres/0003_spend_ledger.sql

BEGIN;

CREATE TABLE IF NOT EXISTS spend_ledger (
    policy_id    TEXT  NOT NULL,
    agent_id     TEXT  NOT NULL,
    period_start BIGINT NOT NULL,                 -- unix epoch; 0 = lifetime
    total_usd    DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_updated BIGINT NOT NULL,
    PRIMARY KEY (policy_id, agent_id, period_start)
);
CREATE INDEX IF NOT EXISTS idx_spend_ledger_agent ON spend_ledger(agent_id);

CREATE TABLE IF NOT EXISTS spend_log (
    log_id       TEXT PRIMARY KEY,                -- uuid
    policy_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    action_id    TEXT,                            -- nullable; sdk-provided
    amount_usd   DOUBLE PRECISION NOT NULL,
    recorded_at  BIGINT NOT NULL,
    source       TEXT NOT NULL                    -- 'sdk_flush' | 'server_recompute'
);
CREATE INDEX IF NOT EXISTS idx_spend_log_pa ON spend_log(policy_id, agent_id, recorded_at);

COMMIT;
