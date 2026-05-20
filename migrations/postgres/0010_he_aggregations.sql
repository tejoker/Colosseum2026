-- Sprint 13-14 Tier 2: Paillier homomorphic-encryption aggregation surface.
--
-- One row per (cohort_id, metric_id, period_start) keyed by a stable
-- `aggregation_id`. The server homomorphically sums customer ciphertexts
-- in place; per-customer values are never decrypted server-side. Only
-- the cohort aggregate is decrypted (by an operator holding the cohort
-- private key).
--
-- NEEDS_CRYPTO_REVIEW: this schema has not been audited by a cryptographer.
-- Suitable for development and demo only. Production deployments require
-- third-party review of: modular arithmetic correctness, random sampling
-- distribution, message space encoding, ciphertext re-randomization, and
-- side-channel resistance.

BEGIN;

CREATE TABLE IF NOT EXISTS he_aggregations (
    aggregation_id     TEXT    PRIMARY KEY,
    cohort_id          TEXT    NOT NULL,
    metric_id          TEXT    NOT NULL,
    period_start       BIGINT  NOT NULL,
    pk_id              TEXT    NOT NULL,
    sum_ciphertext_b64 TEXT    NOT NULL,
    n_contributions    BIGINT  NOT NULL DEFAULT 0,
    last_updated       BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_he_agg_cohort
    ON he_aggregations(cohort_id, period_start);

COMMIT;
