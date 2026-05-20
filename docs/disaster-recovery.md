# Disaster Recovery Runbooks

One section per failure mode. Each: **Detection → Containment → Recovery → Preventive measures.** Operator opens this doc when alerts fire. Pentest readers use it to confirm we have rehearsed worst-cases.

Cross-references: `docs/threat-model.md`, `docs/cryptographic-assumptions.md`, `docs/key-rotation.md`, `docs/operations.md`.

---

## 1. Bitcoin OTS calendar unavailable

**Symptom.** `bitcoin_anchor::submit` returns calendar HTTP errors; `bitcoin_merkle_anchors` rows pile up with `ots_receipt_blob = NULL`.

**Detection.**
- Prometheus alert on `sauron_btc_anchor_backlog_seconds > 7200`.
- `tracing` logs from `core/src/bitcoin_anchor.rs` show repeated calendar timeouts.
- `GET /admin/anchor/agent-actions/health` returns `btc_calendar_reachable = false`.

**Containment.**
- Calendar downtime does **not** stop the service. The Solana memo path runs independently and finalises in ≈ 30 s. Action-log integrity is preserved by the Solana anchor alone for the duration of the outage.
- Configure a secondary calendar via `SAURON_BTC_CALENDAR_URLS` (comma-separated). Operator-run calendar acceptable for self-hosting.
- Backlog tolerance: receipts stay queued indefinitely; OTS upgrade is asynchronous by design.

**Recovery.**
- When at least one calendar comes back: existing receipts auto-upgrade on the next sweep. No replay required.
- If all calendars are dead for > 24 h, stand up an internal calendar (Petertodd's reference implementation) and add it to the URL list.

**Preventive measures.**
- Run a self-hosted calendar in parallel to the public ones from day one.
- Alert if backlog > 2 h; page if > 24 h.

---

## 2. Solana RPC down or rate-limiting

**Symptom.** `solana_anchor::submit` returns 429 / 5xx; `solana_merkle_anchors` rows stuck with empty `signature`.

**Detection.**
- Metric `sauron_solana_submit_errors_total` rate spikes.
- Logs from `core/src/solana_anchor.rs` show repeated `getTransaction` / `sendTransaction` failures.

**Containment.**
- Retry with exponential backoff (already in submit path).
- Failover RPC: set `SAURON_SOLANA_RPC_FALLBACK_URLS` (comma-separated). System tries the next URL on persistent failure.
- Bitcoin-only mode: set `SAURON_SOLANA_ANCHOR_ENABLED=0` to skip Solana entirely. Audit log still anchors to Bitcoin OTS — slower but sound.

**Recovery.**
- When RPC recovers: queued submits drain automatically. No data loss.
- For long outages: replay queued anchors via `cargo run --bin agent-action-tool -- solana-flush`.

**Preventive measures.**
- Keep at least two RPC providers configured (e.g., Triton + Helius + own validator).
- Budget SOL fees with 30-day reserve in the anchor wallet.

---

## 3. SQLite database corruption (single-node deployments)

**Symptom.** `core` panics on startup with `SqliteFailure { code: 11, .. }` ("database disk image is malformed") or sqlx returns `ColumnDecode`.

**Detection.**
- Process refuses to boot.
- `sqlite3 sauron.db "PRAGMA integrity_check;"` returns errors.

**Containment.**
- Stop the core process. Do not let it write further to a corrupt file.
- Snapshot the corrupt DB file: `cp sauron.db sauron.db.corrupt.<ts>`.

**Recovery.**
- Restore from the most recent backup. SQLite backup is `litestream replicate`-driven in production; `sqlite3 .dump` for cold copies.
- After restore: replay the anchor log from Bitcoin/Solana to verify any committed receipts since the backup window. Walk `bitcoin_merkle_anchors` newer than backup checkpoint; for each row, fetch the OTS receipt, derive the merkle root, and check the local DB row matches. If the receipt root is on-chain but the DB row is missing, the original transaction was committed before crash — flag for manual review.
- Worst case: receipts created between backup and crash without anchor-roundtrip are lost. Operator notifies tenants of the time window.

**Preventive measures.**
- Use `litestream` or `Postgres` in production. SQLite is only supported for single-tenant / dev deployments.
- WAL-mode is on by default; do not disable it.
- Hourly backup, 30-day retention.

---

## 4. Postgres node loss (primary failover)

**Symptom.** `core` cannot acquire connections; `pg_isready` returns false.

**Detection.**
- Health endpoint `/healthz` returns 503.
- `sqlx::Error::PoolTimedOut`.

**Containment.**
- If running in HA mode (Patroni / Stolon / AWS RDS Multi-AZ): the standby promotes automatically. Core's reconnect loop picks up the new primary.
- If single primary: route reads to the standby; admins block writes until primary recovers.

**Recovery.**
- WAL replay on the promoted standby fully restores state to the last committed transaction. The TOCTOU-safe `UPDATE ... WHERE field = old_value` pattern (see `core/src/main.rs:1108-1148`) guarantees no half-applied updates.
- After failover, run `vacuum analyze` on the new primary.

**Preventive measures.**
- Always deploy Postgres in HA (≥ 1 hot standby).
- Test failover monthly (`pg_promote` drill).
- Keep WAL retention ≥ 24 h on the standby.

---

## 5. Customer DKG share offline

**Symptom.** Threshold signing fails with `not enough shares (k-of-n)`. Specific to deployments using customer-held DKG shares for issuer or admin-multisig.

**Detection.**
- `dkg::sign` returns `InsufficientShares`.
- Customer notifies us their HSM is offline / lost.

**Containment.**
- Operate with the remaining shareholders if quorum (k) still met. The system was designed for this — the share-loss threshold determines availability.
- If quorum lost: protected operations halt. Read-only paths continue.

**Recovery.**
- Replace the lost share via the share-rotation procedure: surviving k-of-n shareholders run `cargo run --bin sauronid-cli -- dkg rotate --add <new-shareholder-pubkey> --remove <lost-shareholder-id>`.
- The protocol issues new shares to all participants and increments the share-set version. Old shares are repudiated.
- Audit trail: rotation event appended to security audit log.

**Preventive measures.**
- Configure k strictly less than n (e.g., 3-of-5, not 5-of-5).
- Rehearse share rotation quarterly.
- Geographic + organisational diversity of shareholders.

---

## 6. Operator admin key compromise

**Symptom.** Unexpected admin endpoint calls in audit log; admin key found in a leaked .env / git history / cloud snapshot.

**Detection.**
- Out-of-window admin API calls.
- Unexpected policy uploads / deletions / agent revokes.
- `/admin/audit/recent` shows entries with no matching operator ticket.

**Containment.**
- Mint a new key. Add it to `SAURON_ADMIN_KEYS` (comma-separated, multi-key supported — see `core/src/admin.rs::build_admin_auth_config`). Restart with both keys active.
- Once all tooling has migrated to the new key, drop the compromised one from `SAURON_ADMIN_KEYS` and restart again. **Zero downtime**: the multi-key path means we never have a moment with no valid admin key.

**Recovery.**
- Audit what the attacker did during the leak window. `/admin/audit/recent?since=<timestamp>` returns all admin actions in chronological order.
- Revoke any agents / policies / tokens minted by the attacker.
- Re-anchor the audit log to lock in the post-compromise state.

**Preventive measures.**
- Production admin keys ≥ 32 random bytes (enforced at startup, see `core/src/admin.rs:99-107`).
- Wrap with Vault Transit or AWS KMS (`SAURON_VAULT_TRANSIT_ENABLED=1` / `SAURON_AWS_KMS_ENABLED=1`).
- Never commit `.env` files; gitleaks / trufflehog in pre-commit.
- Use the JWT-scoped admin path for tooling (`SAURON_ADMIN_JWT_HS256_SECRET`) so each tool has its own short-lived bearer.
- Full procedure: `docs/key-rotation.md` §Operator admin keys.

---

## 7. SDK clock skew on the agent side

**Symptom.** Agent requests return `401 timestamp outside skew window`.

**Detection.**
- Spike in `sauron_call_sig_rejected_total{reason="skew"}`.
- `tracing` events from `require_call_signature` (`core/src/agent.rs:1587`) with `reason=skew`.

**Containment.**
- Verify the agent host has NTP sync. `chronyc tracking` or `timedatectl status`.
- Acceptable skew is `SAURON_CALL_SIG_SKEW_MS` (default 60 s). Widening this is **not recommended** — it expands the replay window.

**Recovery.**
- Fix the agent's clock. NTP restart, container restart with `--hostname-host-time` if running rootless.
- Diagnostic logs to look at: client-side request log shows the `ts` it embedded; server-side `tracing` shows received `ts` and server `now`. Diff confirms direction of skew.

**Preventive measures.**
- All agent hosts must run NTP / chrony.
- Monitor `sauron_call_sig_rejected_total` per agent_id to catch silent skew on a specific deployment.

---

## 8. ZK ceremony key compromise

**Symptom.** Trusted-setup toxic waste leaked or suspected; ZK circuit's `verification_key.json` should no longer be trusted.

**Detection.**
- Whistleblower / breach disclosure from a ceremony participant.
- Anomalous proof acceptance patterns (proofs verifying that *should not* exist).

**Containment.**
- All proofs already verified under the compromised vk are now **forgeable in principle**. Treat any post-compromise proof as unsound.
- Switch the affected circuit's `verifier_mode` to `reject_all` in `zkp/ceremony/circuits-list.json` until a fresh ceremony runs.
- Tenants notified that ZK-only claims (aggregated stats, action-log proofs) are paused. Bitcoin / Solana anchors remain valid — they are not derived from the ceremony.

**Recovery.**
- Re-run the multi-party ceremony for the affected circuit per `zkp/ceremony/README.md`. Different participants, fresh entropy.
- Publish the new `vk_id` (it changes on every fresh setup — see `core/src/zk_verifier.rs:44`). Verifiers reject proofs under the old `vk_id`.
- Re-aggregate any stats from raw logs under the new vk. Old proofs are NOT re-verifiable; the raw audit log (anchored to Bitcoin / Solana) is the source of truth.

**Preventive measures.**
- Minimum 3 independent ceremony parties (see `circuits-list.json::contributors_required`).
- At least one party must publicly attest to destroying toxic waste.
- Rotate the ceremony every major release.
- Until a real ceremony runs: document loudly that current dev vk is unsound (already done in `docs/cryptographic-assumptions.md` §8 and the ceremony README).

---

## 9. Tenant data wipe request (GDPR Article 17 — Right to erasure)

**Symptom.** Tenant submits a verified wipe request for `tenant_id = X`.

**Detection.**
- Operator legal counsel forwards request. Verify identity per `docs/subpoena-response.md` §Process.

**Containment.**
- Pause the tenant. `POST /admin/tenants/{id}/pause` (admin write key required).
- Notify tenant of which-data-can-be-wiped vs which-is-anchored-on-chain.

**Recovery — tables to purge:**

| Table | Action |
|---|---|
| `agents` (WHERE `tenant_id = X`) | Delete rows. Foreign-key cascade handles dependents. |
| `agent_action_receipts` | Delete rows. The merkle batch root may already be anchored on Bitcoin/Solana; the leaf hash remains on-chain but the pre-image (the receipt JSON) is gone. The on-chain root proves *something* existed, not *what*. |
| `agent_egress_log` | Delete rows scoped to tenant agents. |
| `agent_call_nonces` | Delete (no PII, can leave). |
| `ajwt_used_jtis` | Delete (no PII). |
| `policy_documents` | Delete rows scoped to tenant. |
| `spend_log` | Delete rows where `agent_id` in tenant's set. |
| `customer_stats` | Delete rows where `tenant_id = X` (`core/src/aggregation/store.rs`). |
| `consent_logs`, `kyc_*` (if enabled) | Delete per legal counsel scope. |

**Anchor immutability caveat.** Once a receipt's leaf hash is in a Bitcoin block, the hash itself cannot be removed. The legal position is: the on-chain hash is not personal data because the pre-image is destroyed. Document this in the response letter to the data subject.

**Preventive measures.**
- Per-tenant pause flag honoured everywhere via tenancy middleware.
- Tenant-scoped DELETE primitives tested in integration suite.
- Operator legal counsel must sign off before any wipe — see `docs/subpoena-response.md`.

---

## Detection summary (quick reference)

| Failure mode | Primary alert |
|---|---|
| Bitcoin OTS down | `sauron_btc_anchor_backlog_seconds > 7200` |
| Solana RPC down | `sauron_solana_submit_errors_total` rate > threshold |
| SQLite corruption | Boot fails with `SqliteFailure { code: 11 }` |
| Postgres failover | `/healthz` 503 |
| DKG quorum lost | `dkg::sign` returns `InsufficientShares` |
| Admin key leak | `/admin/audit/recent` anomaly |
| Clock skew | `sauron_call_sig_rejected_total{reason="skew"}` |
| ZK ceremony leak | External disclosure |
| GDPR wipe | Operator-initiated |
