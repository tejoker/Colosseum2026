-- Receipt hash chain (per tenant).
--
-- A per-receipt signature proves a receipt was not edited. It cannot prove none
-- were removed: nothing references the receipt before it. `seq` is dense and
-- monotonic per tenant and `prev_hash` is the chain hash of seq-1, so a deleted
-- or reordered receipt breaks the successor's link and shows up as a gap.
--
-- Existing rows keep seq = 0 / prev_hash = '' and remain verifiable under the
-- v2 receipt signature; new receipts chain from seq 1 upward.
ALTER TABLE agent_action_receipts
    ADD COLUMN IF NOT EXISTS seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agent_action_receipts
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_tenant_seq
    ON agent_action_receipts (tenant_id, seq);
