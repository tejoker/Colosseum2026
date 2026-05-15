# SauronID engineering roadmap

Living document. Each plan tracks a multi-week initiative; milestones (M1/M2/...)
are concrete, ship-able increments.

## Recently shipped — 2026-05-15

Two-session sprint delivered the following:

- **Honest README rewrite** — removed false KMS / Nitro / Vault claims, added an
  explicit Trust model section, corrected fail-closed wording.
- **Hackathon-grade artifact removal** — `scripts/dev_secrets.sh` helper,
  `.dev-secrets` added to `.gitignore`, CI key rotation in place.
- **25 HTTP-boundary panics** replaced with structured `AppError` (no more
  `unwrap()` / `expect()` on request paths).
- **15 cargo audit advisories → 0** via a single-line `Cargo.toml` fix that
  drops `sqlx` default features (kills the transitive yanked-crate tail).
- **Dynamic A11-A16 redteam tests** — 16/16 scenarios now exercise live code
  paths; no more code-review handwave entries.
- **Anchor ADR-001 implemented** — three-state surface (Solana-confirmed /
  BTC-pending / Dually anchored) and deprecated the boolean `anchored` field.
  Documented in `README.md` under the OpenTimestamps section.
- **Postgres M1-M4** — txn helpers + 14 modules ported + race tests + CI matrix.
- **TPM2 M1-M2** — TPMS_ATTEST parser + AIK signature verification +
  EK->AIK cert-chain walker skeleton + `ServerDerived` gating.
- **Benchmark scaffold** — `sauron`, `dpop`, and `http-sig` (RFC 9421) targets
  produce real numbers; `auth0` is gated on env credentials; `aws-sts` deferred.
- **~70 new unit tests** (26 + 25 + 8 + 6 + 6) across merkle, repository,
  state, and attestation modules.
- **`deny.toml` + cargo-audit GitHub Action** with a weekly cron.

## Plan 1 — TPM2-bound proof-of-possession key (4-6 weeks)

**Goal**: remove the implicit trust assumption that operator compromise of
`jwt_secret` equals full agent impersonation. Today agent PoP keys are derived
server-side as `SHA256(jwt_secret | agent_id | human_key_image | agent_checksum)`,
so an attacker with `jwt_secret` can mint a valid signature for any agent. Bind
the PoP key to a TPM2 device so the private material never leaves the hardware.

### M1 — Opt-in legacy path and TPM2 quote intake (shipped 2026-05-15)

- Add `AttestationKind::ServerDerived` as an explicit enum variant (no longer
  implicit).
- Refuse `ServerDerived` in production unless `SAURON_ALLOW_SERVER_DERIVED_POP=1`
  is set, OR `ENV=development`. Default = refuse.
- `Tpm2Quote` verifier: parse the five-field operator payload
  (`quote_b64`, `attest_b64`, `signature_b64`, `aik_cert_pem`,
  `ek_cert_chain_pem`). Return `AttestationError::PartialImplementation` when
  parsing succeeds, `Malformed` on missing fields / bad base64 / missing PEM
  markers. No `tss-esapi` dep yet — pure Rust parsing.
- Schema: add three nullable columns to `agents`:
  `attestation_pubkey_b64u`, `attestation_pcr_set`,
  `attestation_ek_cert_chain_pem`. Both SQLite (idempotent `ALTER`) and
  Postgres (`CREATE TABLE` + idempotent `ALTER ... IF NOT EXISTS`).
- `RegisterAgentRequest` accepts the five `tpm2_*` fields plus
  `tpm2_pcr_set` + `tpm2_attestation_pubkey_b64u`. All five quote fields are
  required when `attestation_kind == "tpm2_quote"`.
- `[features] tpm2 = []` stub in `core/Cargo.toml` so future TPM2 deps
  (`tss-esapi` -> `libtss2-esys`) can be gated.

### M2 — TPM2 quote verification (shipped 2026-05-15)

- Real **TPMS_ATTEST parser** (pure Rust, byte-level deserialiser, no `nom`
  dep). Validates magic, type, qualifiedSigner length, extraData, clock, PCR
  digest, and selection bitfield.
- **AIK signature verification** via `ring` covering the three algorithms
  fielded by current TPM vendors:
  - Ed25519
  - ECDSA-P256 (SHA-256)
  - RSA-PKCS1 v1.5 (SHA-256)
- **EK -> AIK certificate chain walker skeleton** using `webpki`. Operator
  supplies vendor root certificates via `SAURON_TPM2_VENDOR_ROOTS_DIR`
  (Infineon, STMicro, Microsoft, Intel, AMD, IBM). Chain validation runs
  before signature check; failures surface as `AttestationError::ChainInvalid`.
- **PCR digest comparison** against the operator-registered measurement at
  registration time. Mismatch -> `AttestationError::PcrMismatch`.

### M3 — TPM2-rooted PoP signing (DEFERRED, target Q3 2026)

Replace server-side PoP key derivation with a "PoP pubkey supplied at
registration" flow when `attestation_kind == "tpm2_quote"`. Per-call DPoP-style
signatures verified against the AIK-bound pubkey rather than the derived key.

**Why deferred**: architectural cutover with hardware dependency cannot ship in
a single dev cycle without breaking existing deployments. Requires:

- Deprecation cycle for existing agents (minimum one quarter).
- Real TPM hardware testing on Infineon SLB 9670, STMicro ST33, and fTPM.
- Client SDK rewrites: Python (`tpm2-pytss`), TypeScript (subprocess wrapper
  around `tpm2-tools`).
- `swtpm` integration into CI for hermetic test coverage.

### M4 — Remove `ServerDerived` variant (DEFERRED beyond M3)

After the M3 cutover window closes, remove `AttestationKind::ServerDerived`
entirely. Depends on M3 shipping and the deprecation window expiring.

## Plan 2 — Postgres backend completion (5 weeks)

**Goal**: replace the single-node `sqlite + r2d2 + rusqlite` storage path with
`sqlx + PgPool` for production. The legacy path stays as a dev fallback. Each
milestone re-runs the 9-scenario invariant suite + the TOCTOU race scenario
before flipping the next table.

### M1 — Serializable transaction helper + first 3 modules (shipped 2026-05-15)

- `core/src/repository.rs::Repo::txn_immediate_sqlite` — SQLite branch wraps
  the closure in `BEGIN IMMEDIATE TRANSACTION` + commit / rollback.
- `core/src/repository.rs::Repo::txn_serializable_pg` — Postgres branch runs
  under `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE` with `SQLSTATE 40001`
  retry (3 attempts, 10/40/90 ms backoff). Outer caller never sees the retry.
- Repo helpers routed through the wrappers (M1 modules):
  - `Repo::consume_call_nonce` — `agent_call_nonces` single-use insert.
  - `Repo::consume_ajwt_jti` — `ajwt_used_jtis` single-use insert.
  - `Repo::risk_increment` — `risk_rate_counters` INSERT-ON-CONFLICT-UPDATE
    -RETURNING.
- Legacy sync helpers (`ajwt_support::consume_ajwt_jti`,
  `ajwt_support::consume_call_nonce`, `risk::check_and_increment`) wrap their
  existing SQL in `BEGIN IMMEDIATE` so call sites that still hold a
  `MutexGuard<Connection>` get the same isolation guarantee.
- `redteam/src/scenarios/postgres-toctou-race.ts` — N=50 concurrent
  `/agent/payment/authorize` calls reusing one nonce; asserts exactly 1 winner
  + 49 x HTTP 409. Skips unless `SAURON_DB_BACKEND=postgres`.
- `.github/workflows/test.yml` two jobs:
  - `test-sqlite` — `cargo check --lib` + `cargo test --lib` on default backend.
  - `test-postgres` — boots `postgres:16-alpine`, applies
    `migrations/postgres/0001_initial.sql`, runs M1 unit tests + race scenario.

### M2 — TOCTOU-sensitive consume tables (shipped 2026-05-15)

Four replay-sensitive tables ported. All Postgres paths use
`SELECT FOR UPDATE` + `RETURNING` to close the read/modify/write window:

- `agent_pop_challenges`
- `bank_attestation_nonces`
- `consent_log`
- `agent_payment_authorizations`

Race scenario expanded to cover each new endpoint; still asserts
1 winner / N-1 conflicts under concurrent reuse.

### M3 — Identity tables (shipped 2026-05-15)

Four identity tables ported. Postgres `BIGSERIAL` handles autoincrement
columns that previously relied on SQLite `INTEGER PRIMARY KEY`:

- `credential_codes`
- `agents` + checksum tables
- `users` + credentials + registrations
- `merkle_leaves`

Lower contention than M2; mostly mechanical SQL dialect work.

### M4 — Anchor tables (shipped 2026-05-15)

Three anchor tables ported:

- `bitcoin_merkle_anchors`
- `solana_merkle_anchors`
- `agent_action_receipts`

After M4 the rusqlite path is feature-complete in Postgres. Staging cuts
over; the SQLite path remains as a dev fallback. Full confidence-suite run
on Postgres before flipping production.

### M5 — Decommission single-node-SQLite acknowledgement (DEFERRED, target Q3 2026)

Remove the `SAURON_ACCEPT_SINGLE_NODE_SQLITE` requirement from the production
profile in `docs/operations.md`, archive the SQLite backend behind a
`#[cfg(feature = "legacy-sqlite")]` flag, switch default features to
`["postgres"]`.

**Why deferred**: customer-config break. Needs proper migration tooling, a
deprecation announcement, and at least one minor-version cycle before flip.
Doing this hot would strand existing dev installs.

See `docs/operations.md` for backend env vars + the "Phase 3" porting pattern.

## Plan 3 — Anchor path simplification (shipped 2026-05-15)

ADR-001 implemented. The dashboard and `/admin/anchor/batches` /
`/anchors` console page now surface three honest states per batch:

- **Solana-confirmed** (<= 30 s memo finalisation)
- **BTC-pending** (<= 1 h OpenTimestamps Bitcoin block inclusion)
- **Dually anchored** (both chains confirmed)

The legacy boolean `anchored` field is deprecated but still emitted for one
release cycle so existing dashboards don't break. Operators with stricter
timing requirements pick the Solana-only path or run their own OpenTimestamps
calendar. Documented in `README.md` under the OpenTimestamps section.

No outstanding milestones for this plan.

## Plan 4 — Hardware-attestation breadth (SGX / SEV / Nitro / Apple)

See `docs/threat-model.md`. Same shape as Plan 1: M1 parses, M2 verifies, M3
binds the PoP key. Each kind shipped independently. No active milestones in
flight; queued behind Plan 1 M3.

## Deferred items — explicit list with rationale

| Item | Plan | Reason | Earliest |
|---|---|---|---|
| TPM2 M3 cutover | 1 | Needs deprecation cycle + hardware testing | Q3 2026 |
| TPM2 M4 remove `ServerDerived` | 1 | Depends on M3 | Q4 2026 |
| Postgres M5 remove SQLite flag | 2 | Customer-config break, needs migration tool | Q3 2026 |
| AWS STS competitive benchmark | (bench) | Needs paid AWS creds for `AssumeRole` calls | when bench engineer gets AWS account |
| Anthropic MCP comparison | (bench) | Category error (tool protocol, not identity) | won't ship |
| GNAP comparison | (bench) | No production-grade open-source implementation exists | won't ship |
