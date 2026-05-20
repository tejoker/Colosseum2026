# Key Rotation Playbook

Per-key-type: cadence, procedure, blast radius if missed, automation status. Operator runs through this before every key-rotation maintenance window. Pentest readers use it to verify keys are not "forever-keys".

Audit trail rule: **every rotation event MUST leave an entry in the security audit log** (Sprint 12 middleware writes to `core/src/middleware/audit_log.rs`). The audit row is then included in the next agent-action anchor batch — making the rotation itself tamper-evident.

---

## 1. Operator admin keys — `SAURON_ADMIN_KEY` / `SAURON_ADMIN_KEYS`

| Field | Value |
|---|---|
| Cadence | Quarterly, plus immediate on suspected leak. |
| Blast radius if missed | Stale leaked key continues to mint clients, revoke agents, read every tenant's data. |
| Automation | Multi-key support already in code (`core/src/admin.rs::build_admin_auth_config`) so rotation is zero-downtime. |

**Procedure (zero-downtime).**

1. Generate new key: `openssl rand -hex 32` (or HSM-backed equivalent).
2. Append the new key to `SAURON_ADMIN_KEYS` (comma-separated). Existing key stays.
3. Reload the process (SIGHUP if supported, else rolling restart). Both keys are now valid.
4. Update every tool / pipeline / dashboard to use the new key. Verify via `/admin/healthz` from each caller.
5. Once no caller uses the old key: drop the old key from `SAURON_ADMIN_KEYS` and reload again.
6. Append rotation event to audit log.

**Verification.**
- `curl -H "Authorization: Bearer <old-key>" .../admin/healthz` → 401.
- `curl -H "Authorization: Bearer <new-key>" .../admin/healthz` → 200.

---

## 2. JWT signing secret — `SAURON_JWT_SECRET`

| Field | Value |
|---|---|
| Cadence | Annually, plus immediate on suspected leak. |
| Blast radius if missed | Forger holding the secret can mint A-JWTs for any agent. |
| Automation | **Not rotatable in-flight.** This secret is embedded into A-JWT signatures; rotating it invalidates every outstanding A-JWT. |

**Procedure (maintenance window required).**

1. Schedule a maintenance window. Tenants notified.
2. Pause agent issuance: `POST /admin/feature/agent-issuance/pause`.
3. Wait for outstanding A-JWTs to expire (max lifetime: `SAURON_AJWT_TTL_SECS`, default 3600 s = 1 h).
4. Generate new secret: `openssl rand -hex 32`.
5. Update `SAURON_JWT_SECRET` (load via Vault Transit / KMS — never plain env). Restart core.
6. Resume issuance: `POST /admin/feature/agent-issuance/resume`.
7. Every agent re-authenticates and gets a new A-JWT.
8. Append rotation event to audit log.

**Verification.**
- A-JWTs issued before the rotation now return 401 on verify with `invalid signature`.
- A-JWTs issued after the rotation verify cleanly.

**Mitigation for shorter window:** Reduce `SAURON_AJWT_TTL_SECS` (e.g. to 300 s) ahead of the rotation. Trade-off: more reissue traffic.

---

## 3. Token secret — `SAURON_TOKEN_SECRET`

Same constraint as JWT secret. Same procedure. The token secret is used for session HMAC / consent-token derivation; rotating it invalidates every outstanding session.

---

## 4. OPRF seed — `SAURON_OPRF_SEED`

| Field | Value |
|---|---|
| Cadence | Annually or never (operator's call). |
| Blast radius if missed | Operator-side scalar leak means an attacker can deterministically derive every per-tenant key-image. |
| Automation | **Not rotatable without re-onboarding every user.** The OPRF scalar deterministically maps `(passphrase → key-image)`. Rotating the scalar produces a new mapping; every existing user's key-image becomes orphaned. |

**Procedure (breaking change).**

This is a re-onboarding event. Treat it like a major-version migration.

1. Notify every tenant 30+ days in advance.
2. Stand up a parallel deployment with a fresh `SAURON_OPRF_SEED`.
3. Migrate users by having them re-derive on the new deployment.
4. Decommission the old deployment once migration completes.
5. Audit log: rotation event includes a note that the old key-image set is permanently orphaned.

**When to do it.** Only on suspected scalar leak. Even then, weigh against the migration burden — the seed is held only in Vault Transit / KMS, not on disk in plaintext (`core/src/state.rs:170-254`, `core/src/secret_provider.rs`). If those backends are intact, the seed has not actually leaked.

---

## 5. Per-agent PoP keys

| Field | Value |
|---|---|
| Cadence | Agent-initiated, any cadence. Operator can enforce a max age policy. |
| Blast radius if missed | Compromised agent key signs requests as that one agent. Scoped damage. |
| Automation | Fully automated via `POST /agent/{id}/rotate-pop-key` (PoP-protected by the *current* key). |

**Procedure.**

1. Agent generates a fresh Ed25519 keypair (in its TEE / TPM / userland — depends on attestation kind).
2. Agent calls `POST /agent/{id}/rotate-pop-key` with the new public key, signed by the *current* PoP key + per-call signature.
3. Server replaces `pop_public_key_b64u` for that agent. Increments `pop_key_version` for audit.
4. Subsequent calls signed with the old key fail; new key required.
5. Old key entry archived (not deleted) for receipt-verification look-ups against old action receipts.

**For attested keys.** When `attestation_kind = tpm2_quote / nitro_enclave / sgx_quote / sev_snp / arm_cca / apple_secure`, the agent must also re-attest the new key under the same kind. Server cross-checks the new attestation cert chain.

---

## 6. Vault Transit wrapping key

| Field | Value |
|---|---|
| Cadence | Annually (Vault best practice). |
| Blast radius if missed | Old wrapped secrets remain wrapped under the old version; Vault keeps version history, so reads still work. Risk is only at the Vault layer. |
| Automation | Native Vault primitive. |

**Procedure.**

1. `vault write -f transit/keys/sauronid-root/rotate`. New key version created. Old versions retained for decryption.
2. Re-wrap secrets: `vault write transit/rewrap/sauronid-root ciphertext=<old-ciphertext>` → returns ciphertext under the new version.
3. Replace the env var values (`SAURON_JWT_SECRET_WRAPPED`, `SAURON_TOKEN_SECRET_WRAPPED`, `SAURON_OPRF_SEED_WRAPPED`) with the re-wrapped versions.
4. Restart core. Vault decrypts using the new key version.
5. Once confident, `vault write transit/keys/sauronid-root/config min_decryption_version=<new>` to retire old versions.
6. Audit log entry.

**Note.** SauronID itself never sees the wrapping key. It only ever holds plaintext secrets in memory and ciphertext on disk. Wrapping rotation is a Vault-side operation.

---

## 7. AWS KMS key

Same shape as Vault Transit. Documented end-to-end in `docs/operations.md` §KMS-rotation. Procedure: enable automatic annual rotation on the customer-managed key; `core` reads `<NAME>_WRAPPED` env vars and calls `kms:Decrypt` on each (which transparently uses the right key version per AWS).

---

## 8. Bitcoin OTS calendars

No key rotation per se — calendars are URLs, not keys. Operator switches via `SAURON_BTC_CALENDAR_URLS` (comma-separated). To remove a calendar:

1. Drop it from `SAURON_BTC_CALENDAR_URLS`. Restart (or live-reload if hot-reload is wired).
2. Existing OTS receipts that already aggregated through the removed calendar remain valid forever — they were anchored to Bitcoin, not to the calendar's identity.

**No audit-log entry needed** — calendar identities are not authority-bearing.

---

## 9. Solana keypair

| Field | Value |
|---|---|
| Cadence | On suspected leak only. |
| Blast radius if missed | Attacker drains the SOL fee wallet and may impersonate the operator in memo writes. |
| Automation | Manual swap. |

**Procedure (two variants):**

**Hot-swap with empty queue.**
1. Pause anchor submission: set `SAURON_SOLANA_PAUSE_NEW=1`. Existing in-flight anchors drain.
2. When `solana_merkle_anchors` has no pending rows, update `SAURON_SOLANA_KEYPAIR_PATH` to the new keypair file.
3. Fund the new keypair with SOL.
4. Resume: unset the pause flag and restart.
5. Audit log entry.

**Warm-swap with pending memos.**
- Same as above but skip step 2 (don't wait). In-flight rows submitted under the old keypair are accepted by Solana; the new rows go out under the new keypair. Memo body identity is independent of signer. Acceptable for fast rotation.

---

## 10. ZK verification keys

| Field | Value |
|---|---|
| Cadence | Per ceremony — typically major release boundaries. |
| Blast radius if missed | An unrevoked compromised vk lets attackers forge proofs. See `docs/disaster-recovery.md` §8 and `docs/cryptographic-assumptions.md` §8. |
| Automation | None — re-ceremony is multi-party, multi-day. |

**Procedure.** Rotating these IS a re-ceremony. Follow `zkp/ceremony/README.md` end-to-end:

1. Phase 1 — reuse existing Powers-of-Tau output (e.g., perpetual ceremony).
2. Phase 2 — per-circuit contribution from at least 3 independent parties.
3. Publish the new `verification_key.json` files in `zkp/circuits/build/<circuit>/`.
4. The verifier (`core/src/zk_verifier.rs::FsVKeyLoader`) tries the PROD path first, falls back to DEV. Replacing the files swaps the vk live.
5. New `vk_id` propagates; verifiers reject proofs under the old `vk_id` (`core/src/zk_verifier.rs:44`).
6. Audit log entry per circuit.

---

## Audit-trail requirement

Every rotation above MUST result in an entry written via the Sprint 12 security audit middleware (`core/src/middleware/audit_log.rs` — landing concurrently with this doc). The middleware:

- Captures `(actor, action, target, timestamp, signed_summary)` for every admin API call.
- Action codes for rotation: `admin_key_added`, `admin_key_removed`, `jwt_secret_rotated`, `oprf_seed_rotated`, `pop_key_rotated`, `vault_wrap_rotated`, `solana_keypair_rotated`, `zk_vk_rotated`.
- Each entry is merkleized into the next agent-action anchor batch → Bitcoin OTS + Solana memo. After-the-fact tampering with rotation history requires forging both chains.

**Verification command.** `GET /admin/audit/rotations?from=<ts>&to=<ts>` returns the audit-log subset for rotations, with merkle proofs.

---

## Cadence summary table

| Key | Default cadence | Zero-downtime? | Audit code |
|---|---|:-:|---|
| `SAURON_ADMIN_KEY` / `_KEYS` | Quarterly | Yes (multi-key) | `admin_key_*` |
| `SAURON_JWT_SECRET` | Annual | No (window) | `jwt_secret_rotated` |
| `SAURON_TOKEN_SECRET` | Annual | No (window) | `token_secret_rotated` |
| `SAURON_OPRF_SEED` | On leak only | No (re-onboarding) | `oprf_seed_rotated` |
| Per-agent PoP key | Agent-initiated | Yes | `pop_key_rotated` |
| Vault Transit wrap | Annual | Yes | `vault_wrap_rotated` |
| AWS KMS key | Annual (auto) | Yes | `kms_rotated` |
| Bitcoin OTS calendar URL | Ad-hoc | Yes | n/a (no key) |
| Solana keypair | On leak | Mostly | `solana_keypair_rotated` |
| ZK verification key | Per release | No (re-ceremony) | `zk_vk_rotated` |
