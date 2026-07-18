-- Security protocol v2: one-time, identity- and PoP-bound registration
-- challenges. A quote is useful only for the authenticated tenant/user and
-- public key for which the challenge was issued.
CREATE TABLE IF NOT EXISTS agent_attestation_challenges (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    human_key_image     TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    pop_public_key_b64u TEXT NOT NULL,
    expires_at          BIGINT NOT NULL,
    used_at             BIGINT
);

CREATE INDEX IF NOT EXISTS idx_agent_attestation_challenges_exp
    ON agent_attestation_challenges(expires_at);

CREATE TABLE IF NOT EXISTS agent_egress_capabilities (
    token_hash_hex    TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    method            TEXT NOT NULL,
    url               TEXT NOT NULL,
    body_hash_hex     TEXT NOT NULL,
    action_receipt_id TEXT NOT NULL,
    expires_at        BIGINT NOT NULL,
    used_at           BIGINT
);

CREATE INDEX IF NOT EXISTS idx_agent_egress_capabilities_exp
    ON agent_egress_capabilities(expires_at);

CREATE TABLE IF NOT EXISTS zk_proof_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    circuit       TEXT NOT NULL,
    merkle_root   TEXT NOT NULL,
    tree_size     BIGINT NOT NULL,
    anchor_id     TEXT NOT NULL,
    finalized_at  BIGINT NOT NULL,
    UNIQUE (tenant_id, circuit, anchor_id)
);

CREATE INDEX IF NOT EXISTS idx_zk_proof_checkpoints_lookup
    ON zk_proof_checkpoints(tenant_id, checkpoint_id, circuit);

ALTER TABLE customer_stats
    ADD COLUMN IF NOT EXISTS checkpoint_id TEXT NOT NULL DEFAULT '';

ALTER TABLE agent_action_anchors
    ADD COLUMN IF NOT EXISTS anchor_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE agent_action_anchors
    ADD COLUMN IF NOT EXISTS anchor_error TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_action_anchors
    ADD COLUMN IF NOT EXISTS leaf_version BIGINT NOT NULL DEFAULT 1;

-- Database-enforced uniqueness closes concurrent registration races that a
-- SELECT-before-INSERT check cannot prevent.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_public_key
    ON agents(tenant_id, public_key_hex)
    WHERE revoked = 0 AND public_key_hex <> '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_ring_key_image
    ON agents(tenant_id, ring_key_image_hex)
    WHERE revoked = 0 AND ring_key_image_hex <> '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_pop_key
    ON agents(tenant_id, pop_public_key_b64u)
    WHERE revoked = 0 AND pop_public_key_b64u <> '';
