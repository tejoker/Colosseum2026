-- SauronID Postgres schema, version 2 — agent policy DSL store.
--
-- Sprint 2: persistent home for parsed/compiled agent-binding policies.
-- The SQLite path adds the equivalent table inside
-- `core/src/db.rs::init_schema` (see CREATE TABLE policies block).
--
-- Apply via: sqlx migrate run --source migrations/postgres
--   or:      psql "$DATABASE_URL" -f migrations/postgres/0002_policies.sql

BEGIN;

CREATE TABLE IF NOT EXISTS policies (
    policy_id   TEXT   PRIMARY KEY,
    agent       TEXT   NOT NULL,
    version     TEXT   NOT NULL,
    raw_yaml    TEXT   NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_agent ON policies(agent);

COMMIT;
