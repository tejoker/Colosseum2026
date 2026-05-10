use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

pub struct DbHandle {
    pool: Pool<SqliteConnectionManager>,
}

impl DbHandle {
    pub fn lock(&self) -> Result<PooledConnection<SqliteConnectionManager>, r2d2::Error> {
        self.pool.get()
    }
}

/// Opens persistent SQLite (path from DATABASE_PATH, default ./sauron.db).
pub fn open_db() -> DbHandle {
    let path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./sauron.db".to_string());
    let pool_size: u32 = std::env::var("SAURON_DB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v.clamp(1, 64))
        .unwrap_or(16);

    let manager = SqliteConnectionManager::file(&path).with_init(|conn| {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = NORMAL;
            ",
        )
    });

    let pool = Pool::builder()
        .max_size(pool_size)
        .build(manager)
        .unwrap_or_else(|e| panic!("cannot open SQLite pool at '{}': {}", path, e));

    {
        let conn = pool.get().unwrap_or_else(|e| {
            panic!(
                "cannot acquire SQLite connection for init at '{}': {}",
                path, e
            )
        });
        init_schema(&conn);
    }

    println!(
        "[DB] SQLite opened at '{}' with pool_size={}.",
        path, pool_size
    );

    DbHandle { pool }
}

pub fn init_schema(conn: &Connection) {
    conn.execute_batch(
        r#"
        -- Partner sites (banks + retail)
        CREATE TABLE IF NOT EXISTS clients (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            public_key_hex  TEXT    NOT NULL,
            private_key_hex TEXT    NOT NULL,
            key_image_hex   TEXT    NOT NULL,
            tokens_b        INTEGER NOT NULL DEFAULT 0,
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY', 'BANK'))
        );

        -- Registered users
        CREATE TABLE IF NOT EXISTS users (
            key_image_hex   TEXT PRIMARY KEY,
            public_key_hex  TEXT NOT NULL,
            first_name      TEXT NOT NULL DEFAULT '',
            last_name       TEXT NOT NULL DEFAULT '',
            email           TEXT NOT NULL DEFAULT '',
            date_of_birth   TEXT NOT NULL DEFAULT '',
            nationality     TEXT NOT NULL DEFAULT ''
        );

        -- Optional mapping from bank customer IDs to user key images
        CREATE TABLE IF NOT EXISTS bank_kyc_links (
            bank_customer_id TEXT PRIMARY KEY,
            user_key_image   TEXT NOT NULL,
            updated_at       INTEGER NOT NULL,
            metadata_json    TEXT NOT NULL DEFAULT '{}'
        );

        -- Bank attestation replay protection for webhook-based user registration
        CREATE TABLE IF NOT EXISTS bank_attestation_nonces (
            provider_id TEXT NOT NULL,
            nonce       TEXT NOT NULL,
            issued_at   INTEGER NOT NULL,
            PRIMARY KEY (provider_id, nonce)
        );

        -- BabyJubJub ZKP credentials (cached after issuer claim)
        CREATE TABLE IF NOT EXISTS user_credentials (
            key_image_hex   TEXT PRIMARY KEY,
            credential_json TEXT NOT NULL,
            issued_at       INTEGER NOT NULL
        );

        -- ZKP pre-auth codes (stored at user registration, claimed on first credential fetch)
        CREATE TABLE IF NOT EXISTS credential_codes (
            key_image_hex   TEXT    PRIMARY KEY,
            pre_auth_code   TEXT    NOT NULL,
            subject_did     TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            claimed         INTEGER NOT NULL DEFAULT 0
        );

        -- User <-> client relationship
        CREATE TABLE IF NOT EXISTS user_registrations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name        TEXT    NOT NULL,
            user_key_image_hex TEXT    NOT NULL,
            source             TEXT    NOT NULL DEFAULT 'register',
            timestamp          INTEGER NOT NULL,
            UNIQUE(client_name, user_key_image_hex, source)
        );

        -- Consent log (GDPR-auditable)
        CREATE TABLE IF NOT EXISTS consent_log (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id         TEXT    UNIQUE NOT NULL,
            user_key_image     TEXT    NOT NULL DEFAULT '',
            site_name          TEXT    NOT NULL,
            requested_claims_json TEXT NOT NULL DEFAULT '[]',
            granted_at         INTEGER NOT NULL DEFAULT 0,
            consent_expires_at INTEGER NOT NULL DEFAULT 0,
            consent_token      TEXT    UNIQUE,
            token_used         INTEGER NOT NULL DEFAULT 0,
            revoked            INTEGER NOT NULL DEFAULT 0,
            issuing_agent_id   TEXT    DEFAULT NULL
        );

        -- AI agents delegated by human owners
        CREATE TABLE IF NOT EXISTS agents (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id         TEXT    UNIQUE NOT NULL,
            human_key_image  TEXT    NOT NULL,
            agent_checksum   TEXT    NOT NULL,
            intent_json      TEXT    NOT NULL DEFAULT '{}',
            assurance_level  TEXT    NOT NULL DEFAULT 'delegated_nonbank'
                                      CHECK(assurance_level IN ('delegated_bank','delegated_nonbank','autonomous_web3')),
            public_key_hex   TEXT    NOT NULL DEFAULT '',
            ring_key_image_hex TEXT   NOT NULL DEFAULT '',
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );

        -- Agent VCs (self-sovereign KYA path)
        CREATE TABLE IF NOT EXISTS agent_vcs (
            agent_id        TEXT    PRIMARY KEY,
            vc_json         TEXT    NOT NULL,
            vc_hash         TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0
        );

        -- Trusted device tokens (silent re-auth)
        CREATE TABLE IF NOT EXISTS device_tokens (
            token_hash       TEXT    PRIMARY KEY,
            user_key_image   TEXT    NOT NULL,
            site_name        TEXT    NOT NULL,
            fingerprint_hash TEXT    NOT NULL,
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );

        -- API usage billing (per-call metering)
        -- action: 'kyc_human' | 'kyc_agent' | 'zkp_login' | 'agent_register' | 'agent_vc_issue'
        CREATE TABLE IF NOT EXISTS api_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            is_agent    INTEGER NOT NULL DEFAULT 0,
            timestamp   INTEGER NOT NULL,
            meta        TEXT    NOT NULL DEFAULT '{}'
        );

        -- Merkle commitment ledger
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            seq             INTEGER PRIMARY KEY AUTOINCREMENT,
            commitment_hex  TEXT    NOT NULL UNIQUE,
            registered_at   INTEGER NOT NULL
        );

        -- Anonymous request log
        CREATE TABLE IF NOT EXISTS requests_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            action_type TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'OK',
            detail      TEXT    NOT NULL DEFAULT ''
        );

        -- Pre-computed analytics
        CREATE TABLE IF NOT EXISTS company_data (
            company_id  INTEGER NOT NULL,
            data_type   TEXT    NOT NULL CHECK(data_type IN ('stats', 'forecast', 'fraud_summary', 'fraud_recent')),
            data_json   TEXT    NOT NULL,
            PRIMARY KEY (company_id, data_type)
        );

        CREATE INDEX IF NOT EXISTS idx_consent_log_token ON consent_log (consent_token, token_used, revoked, consent_expires_at);
        CREATE INDEX IF NOT EXISTS idx_consent_log_request ON consent_log (request_id, token_used, revoked);
        CREATE INDEX IF NOT EXISTS idx_agents_human_active ON agents (human_key_image, revoked, expires_at);
        CREATE INDEX IF NOT EXISTS idx_api_usage_client_ts ON api_usage (client_name, timestamp);

        -- A-JWT jti replay protection (server authoritative)
        CREATE TABLE IF NOT EXISTS ajwt_used_jtis (
            jti     TEXT PRIMARY KEY NOT NULL,
            exp     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ajwt_used_jtis_exp ON ajwt_used_jtis(exp);

        -- One-time PoP challenges for /agent/pop/challenge
        CREATE TABLE IF NOT EXISTS agent_pop_challenges (
            id          TEXT PRIMARY KEY NOT NULL,
            agent_id    TEXT NOT NULL,
            challenge   TEXT NOT NULL,
            exp         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_pop_challenges_exp ON agent_pop_challenges(exp);

        -- Server-computed agent checksum inputs.
        -- Operators submit a structured config object at /agent/register; the server
        -- canonicalises it to JSON, computes SHA-256, and stores BOTH the raw inputs
        -- and the resulting checksum. Operator-supplied agent_checksum on the agents
        -- row is no longer trusted — it must equal the server-computed value or
        -- the registration is rejected.
        --
        -- agent_type drives required-fields validation (see agent.rs::validate_checksum_inputs).
        CREATE TABLE IF NOT EXISTS agent_checksum_inputs (
            agent_id          TEXT PRIMARY KEY NOT NULL,
            agent_type        TEXT NOT NULL,         -- llm | mcp_server | rule_bot | browser | openai_assistant | framework | custom
            inputs_canonical  TEXT NOT NULL,         -- canonical-JSON of the structured config
            computed_checksum TEXT NOT NULL,         -- sha256:<hex(SHA256(inputs_canonical))>
            version           INTEGER NOT NULL DEFAULT 1,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL
        );

        -- Append-only audit trail for every checksum rotation. Every accepted update
        -- adds a row with the previous and new checksum + caller-supplied reason.
        CREATE TABLE IF NOT EXISTS agent_checksum_audit (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id          TEXT NOT NULL,
            from_checksum     TEXT NOT NULL,
            to_checksum       TEXT NOT NULL,
            from_inputs_hash  TEXT NOT NULL,
            to_inputs_hash    TEXT NOT NULL,
            reason            TEXT NOT NULL DEFAULT '',
            actor             TEXT NOT NULL DEFAULT '',  -- session key_image_hex or admin
            ts                INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_checksum_audit_agent ON agent_checksum_audit(agent_id, ts);

        -- Agent egress log (Gap 2): every outbound call the agent makes to a
        -- third-party API SHOULD be reported here via POST /agent/egress/log.
        -- This is voluntary reporting today; operators are expected to enforce
        -- the constraint via container network policy (e.g. only allow the
        -- agent process to reach SauronID's outbound proxy port). Each row is
        -- included in the next agent-action anchor batch, making after-the-fact
        -- log tampering require forging Bitcoin and Solana attestations.
        CREATE TABLE IF NOT EXISTS agent_egress_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id      TEXT NOT NULL,
            target_host   TEXT NOT NULL,
            target_path   TEXT NOT NULL DEFAULT '',
            method        TEXT NOT NULL,
            body_hash_hex TEXT NOT NULL DEFAULT '',
            status_code   INTEGER NOT NULL DEFAULT 0,
            ts            INTEGER NOT NULL,
            allowed       INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_agent_egress_log_agent_ts ON agent_egress_log(agent_id, ts);

        -- Per-call signature nonces: single-use replay protection for the
        -- DPoP-style call signature over body+method+path+ts+nonce.
        CREATE TABLE IF NOT EXISTS agent_call_nonces (
            agent_id    TEXT    NOT NULL,
            nonce       TEXT    NOT NULL,
            exp         INTEGER NOT NULL,
            PRIMARY KEY (agent_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_call_nonces_exp ON agent_call_nonces(exp);

        -- Cryptographic action leash: each agent action must present a ring
        -- signature over a canonical envelope with a one-time nonce.
        CREATE TABLE IF NOT EXISTS agent_action_nonces (
            nonce       TEXT PRIMARY KEY NOT NULL,
            agent_id    TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            expires_at  INTEGER NOT NULL,
            used_at     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_nonces_exp ON agent_action_nonces(expires_at);

        CREATE TABLE IF NOT EXISTS agent_action_receipts (
            receipt_id         TEXT PRIMARY KEY NOT NULL,
            action_hash        TEXT NOT NULL,
            agent_id           TEXT NOT NULL,
            ring_key_image_hex TEXT NOT NULL,
            policy_version     TEXT NOT NULL,
            ajwt_jti           TEXT NOT NULL,
            pop_jkt            TEXT NOT NULL DEFAULT '',
            status             TEXT NOT NULL,
            signature          TEXT NOT NULL,
            created_at         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_agent ON agent_action_receipts(agent_id, created_at);

        -- Strict, pre-Stripe payment authorization artifacts (single-use auth envelope).
        CREATE TABLE IF NOT EXISTS agent_payment_authorizations (
            auth_id        TEXT PRIMARY KEY NOT NULL,
            agent_id       TEXT NOT NULL,
            jti            TEXT NOT NULL UNIQUE,
            amount_minor   INTEGER NOT NULL,
            currency       TEXT NOT NULL,
            merchant_id    TEXT NOT NULL DEFAULT '',
            payment_ref    TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            expires_at     INTEGER NOT NULL,
            consumed       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_agent ON agent_payment_authorizations(agent_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_payment_ref ON agent_payment_authorizations(payment_ref);

        -- Payment SMT leaves: key = SHA256(agent_id|window_start), value = 0 (no payment) or 1 (consumed).
        -- Root is recomputed in-memory at startup from these rows.
        CREATE TABLE IF NOT EXISTS payment_smt_leaves (
            key_hex     TEXT    PRIMARY KEY NOT NULL,
            value       INTEGER NOT NULL DEFAULT 0,
            updated_at  INTEGER NOT NULL
        );

        -- Bitcoin anchoring receipts for Merkle roots.
        -- Default provider is local mock: OP_RETURN payload + fake txid, no real BTC.
        CREATE TABLE IF NOT EXISTS bitcoin_merkle_anchors (
            anchor_id          TEXT PRIMARY KEY NOT NULL,
            merkle_root_hex    TEXT NOT NULL,
            provider           TEXT NOT NULL,
            network            TEXT NOT NULL,
            op_return_hex      TEXT NOT NULL,
            txid               TEXT NOT NULL,
            broadcast          INTEGER NOT NULL DEFAULT 0,
            no_real_money      INTEGER NOT NULL DEFAULT 1,
            created_at         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bitcoin_merkle_root ON bitcoin_merkle_anchors(merkle_root_hex);

        -- Agent-action anchor batches: periodic merkle commitment over the
        -- agent_action_receipts table, with cross-reference to the BTC OTS and
        -- Solana memo anchors that timestamp the same root. External auditors
        -- replay the merkle path from any receipt to `batch_root_hex` and verify
        -- the root via OTS / Solana Explorer.
        CREATE TABLE IF NOT EXISTS agent_action_anchors (
            anchor_id        TEXT PRIMARY KEY NOT NULL,
            batch_root_hex   TEXT NOT NULL,
            n_actions        INTEGER NOT NULL,
            from_receipt_id  TEXT NOT NULL,   -- inclusive
            to_receipt_id    TEXT NOT NULL,   -- inclusive
            from_created_at  INTEGER NOT NULL,
            to_created_at    INTEGER NOT NULL,
            btc_anchor_id    TEXT NOT NULL DEFAULT '',
            sol_anchor_id    TEXT NOT NULL DEFAULT '',
            created_at       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_root ON agent_action_anchors(batch_root_hex);
        CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_range ON agent_action_anchors(from_created_at, to_created_at);

        -- Solana anchoring receipts for Merkle roots (Memo Program transactions).
        CREATE TABLE IF NOT EXISTS solana_merkle_anchors (
            anchor_id        TEXT PRIMARY KEY NOT NULL,
            merkle_root_hex  TEXT NOT NULL,
            network          TEXT NOT NULL,
            signature        TEXT NOT NULL UNIQUE,
            slot             INTEGER NOT NULL DEFAULT 0,
            confirmed        INTEGER NOT NULL DEFAULT 0,
            created_at       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_solana_merkle_root ON solana_merkle_anchors(merkle_root_hex);
        CREATE INDEX IF NOT EXISTS idx_solana_pending ON solana_merkle_anchors(confirmed, created_at);

        -- Lightning/L402 invoices for agent-paid APIs.
        -- Default provider is local mock: no real sats move during tests.
        CREATE TABLE IF NOT EXISTS lightning_l402_invoices (
            invoice_id      TEXT PRIMARY KEY NOT NULL,
            auth_id         TEXT NOT NULL,
            agent_id        TEXT NOT NULL,
            service         TEXT NOT NULL,
            amount_msat     INTEGER NOT NULL,
            payment_hash    TEXT NOT NULL,
            macaroon        TEXT NOT NULL UNIQUE,
            settled         INTEGER NOT NULL DEFAULT 0,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_lightning_l402_auth ON lightning_l402_invoices(auth_id);
        CREATE INDEX IF NOT EXISTS idx_lightning_l402_agent ON lightning_l402_invoices(agent_id, settled);

        -- Opaque rate-limit buckets (SHA256-derived keys); sliding windows by window_id = floor(epoch/window).
        CREATE TABLE IF NOT EXISTS risk_rate_counters (
            bucket      TEXT NOT NULL,
            window_id   INTEGER NOT NULL,
            cnt         INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket, window_id)
        );
        CREATE INDEX IF NOT EXISTS idx_risk_rate_counters_window ON risk_rate_counters(window_id);

        -- Compliance screening overlays (sanctions / PEP / coarse risk tier) — server-side only.
        CREATE TABLE IF NOT EXISTS user_compliance_screening (
            key_image_hex   TEXT PRIMARY KEY NOT NULL,
            sanctions_tier  TEXT NOT NULL DEFAULT 'unknown',
            pep_flag        INTEGER NOT NULL DEFAULT 0,
            risk_tier       TEXT NOT NULL DEFAULT 'unknown',
            list_version    TEXT NOT NULL DEFAULT '',
            updated_at      INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .expect("DB schema init failed");

    // Migration-safe add for existing databases created before requested_claims_json existed.
    let _ = conn.execute(
        "ALTER TABLE clients ADD COLUMN tokens_b INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE consent_log ADD COLUMN requested_claims_json TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE consent_log ADD COLUMN issuing_agent_id TEXT DEFAULT NULL",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE consent_log ADD COLUMN consent_expires_at INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN assurance_level TEXT NOT NULL DEFAULT 'delegated_nonbank'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN parent_agent_id TEXT DEFAULT NULL",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN pop_jkt TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN pop_public_key_b64u TEXT NOT NULL DEFAULT ''",
        [],
    );

    // OpenTimestamps: per-anchor partial proof bytes (calendar attestations).
    // Promoted to full Bitcoin proofs by the background upgrade task once the
    // calendar root is included in a block. Nullable; absent for legacy mock anchors.
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_receipt_blob BLOB",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_calendar_url TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_upgraded INTEGER NOT NULL DEFAULT 0",
        [],
    );

    // Hardware-attestation slot: TPM2 quote / AWS Nitro attestation document /
    // Apple Secure Enclave attestation. Stored verbatim; SauronID does not
    // cryptographically verify the attestation (see threat-model.md).
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN attestation_blob TEXT",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN attestation_kind TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN ring_key_image_hex TEXT NOT NULL DEFAULT ''",
        [],
    );

    let run_revoke_migration = std::env::var("SAURON_REVOKE_LEGACY_DELEGATED_NONBANK")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(true);

    if run_revoke_migration {
        let revoked = conn
            .execute(
                "UPDATE agents SET revoked = 1 WHERE assurance_level = 'delegated_nonbank' AND revoked = 0",
                [],
            )
            .unwrap_or(0);
        if revoked > 0 {
            println!(
                "[DB][MIGRATION] Revoked {} legacy delegated_nonbank agent(s).",
                revoked
            );
        }
    }

    let _ = conn.execute(
        "INSERT INTO user_compliance_screening (key_image_hex, sanctions_tier, pep_flag, risk_tier, list_version, updated_at)
         SELECT u.key_image_hex, 'unknown', 0, 'unknown', '', 0 FROM users u
         LEFT JOIN user_compliance_screening s ON s.key_image_hex = u.key_image_hex
         WHERE s.key_image_hex IS NULL",
        [],
    );
}
