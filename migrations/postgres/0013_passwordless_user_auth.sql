-- Ceremony-free user authentication.  Registration binds this public key to
-- the user's key image through the existing partner/bank-authenticated path;
-- authentication proves possession with a one-use Ed25519 challenge.
CREATE TABLE IF NOT EXISTS user_auth_credentials (
    key_image_hex           TEXT PRIMARY KEY,
    ed25519_public_key_b64u TEXT UNIQUE NOT NULL,
    created_at              BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_auth_challenges (
    challenge_id  TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    key_image_hex TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    expires_at    BIGINT NOT NULL,
    used_at       BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_user_auth_challenges_expiry
    ON user_auth_challenges(expires_at, used_at);

CREATE TABLE IF NOT EXISTS user_auth_tenant_bindings (
    tenant_id     TEXT NOT NULL,
    key_image_hex TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, key_image_hex)
);

CREATE TABLE IF NOT EXISTS client_tenant_bindings (
    client_name TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    PRIMARY KEY (client_name, tenant_id)
);

INSERT INTO client_tenant_bindings (client_name, tenant_id)
SELECT name, 'default' FROM clients
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS stats_submission_receipts (
    statement_hash TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    checkpoint_id  TEXT NOT NULL,
    metric_id      TEXT NOT NULL,
    submitted_at   BIGINT NOT NULL
);
