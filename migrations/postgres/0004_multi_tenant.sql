-- Sprint 11 multi-tenancy.
--
-- Adds `tenant_id TEXT NOT NULL DEFAULT 'default'` to every tenant-scoped
-- table and creates composite indexes for the (tenant_id, primary_key)
-- partition pattern. Existing rows backfill to the default tenant via the
-- column DEFAULT, preserving backwards compatibility for legacy callers
-- (TS + Python SDKs, dashboard demo, redteam scenarios, simulate_real_actions.py).
--
-- See core/src/tenancy/mod.rs for the audit rationale on which tables are
-- intentionally NOT scoped (users, clients, bank_*, ajwt_used_jtis,
-- agent_call_nonces, agent_pop_challenges, agent_vcs, device_tokens,
-- api_usage, requests_log, company_data, agent_checksum_*,
-- payment_smt_leaves, user_compliance_screening, lightning_l402_invoices).

BEGIN;

-- Each ALTER is `ADD COLUMN IF NOT EXISTS` so re-applying the migration is
-- idempotent (Postgres 9.6+).
ALTER TABLE agents                       ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE policies                     ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_action_receipts        ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_action_anchors         ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE bitcoin_merkle_anchors       ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE solana_merkle_anchors        ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_egress_log             ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE consent_log                  ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_payment_authorizations ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE credential_codes             ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE user_credentials             ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE user_registrations           ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE merkle_leaves                ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE risk_rate_counters           ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE spend_ledger                 ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE spend_log                    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_agents_tenant                 ON agents(tenant_id, human_key_image);
CREATE INDEX IF NOT EXISTS idx_policies_tenant               ON policies(tenant_id, policy_id);
CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_tenant  ON agent_action_receipts(tenant_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_tenant   ON agent_action_anchors(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_bitcoin_merkle_anchors_tenant ON bitcoin_merkle_anchors(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_solana_merkle_anchors_tenant  ON solana_merkle_anchors(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_egress_log_tenant       ON agent_egress_log(tenant_id, agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_consent_log_tenant            ON consent_log(tenant_id, request_id);
CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_tenant     ON agent_payment_authorizations(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_credential_codes_tenant       ON credential_codes(tenant_id, key_image_hex);
CREATE INDEX IF NOT EXISTS idx_user_credentials_tenant       ON user_credentials(tenant_id, key_image_hex);
CREATE INDEX IF NOT EXISTS idx_user_registrations_tenant     ON user_registrations(tenant_id, client_name);
CREATE INDEX IF NOT EXISTS idx_merkle_leaves_tenant          ON merkle_leaves(tenant_id, registered_at);
CREATE INDEX IF NOT EXISTS idx_risk_rate_counters_tenant     ON risk_rate_counters(tenant_id, bucket, window_id);
CREATE INDEX IF NOT EXISTS idx_spend_ledger_tenant           ON spend_ledger(tenant_id, policy_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_spend_log_tenant              ON spend_log(tenant_id, policy_id, agent_id, recorded_at);

COMMIT;
