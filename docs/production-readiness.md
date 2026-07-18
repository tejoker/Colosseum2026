# Production Readiness

SauronID's production claim is limited to the fail-closed agent-control core:
per-agent PoP keys, tenant/audience-bound call signatures, intent and policy
checks, one-use nonces/capabilities, and externally anchored audit receipts.
The repository is not, by itself, evidence that an AI agent cannot escape;
deployment network isolation and independent review remain release gates.

## Demo vs Production

- `ENV=development` enables demo helpers such as `/dev/register_user`, `/dev/buy_tokens`, `/dev/leash/demo`, `/dev/consent_profile`, and development-only mock ZKP proofs.
- Any non-development `ENV` / `SAURON_ENV` rejects dev helpers and requires explicit secrets.
- Mock anchoring is development-only and makes production health fail.
- Local Hardhat is for demos and tests, not production revocation infrastructure.

## Required Controls

- Set strong random `SAURON_ADMIN_KEY` or `SAURON_ADMIN_KEYS`; production rejects admin keys under 32 bytes.
- Set `SAURON_TOKEN_SECRET`, `SAURON_JWT_SECRET`, and
  `SAURON_AUDIT_HMAC_KEY` through a secret manager. Legacy OPRF authentication
  is disabled in production; do not provision `SAURON_OPRF_SEED` as a new
  authentication dependency.
- Set `SAURON_DASHBOARD_SESSION_SECRET` and `SAURON_DASHBOARD_OPERATORS` for the signed dashboard session. Use scrypt records for operator passwords; raw SHA-256 records are development-only.
- Keep the dashboard behind TLS and, where appropriate, the optional Caddy HTTP basic-auth defense-in-depth layer.
- Keep `SAURON_REQUIRE_CALL_SIG`, `SAURON_REQUIRE_AGENT_TYPE`,
  `SAURON_POLICY_REQUIRE_BINDING`, `SAURON_EGRESS_GATEWAY`, and
  `SAURON_ENFORCE_STATS_FRESHNESS` enabled. Production startup refuses an
  explicit disable unless the unsafe override is deliberately set.
- Set a finite positive `SAURON_MAX_ACTION_USD` global damage ceiling.
- Hardware attestation is optional. If selling that separate assurance tier,
  enable both attestation flags and supply authoritative measurements; otherwise
  leave it off and treat agents as hostile.
- Pin both reviewed guest image IDs in
  `SAURON_TRANSPARENT_IMAGE_IDS_JSON`; production startup validates the map.
- Use only structured production egress entries with explicit methods, path,
  byte caps, allowed headers, request-body policy and response disclosure mode.
- Keep legacy OPRF auth, unaudited Paillier, voluntary egress logging,
  server-derived PoP, custom checksums, legacy token MAC, and Groth16 disabled.
- Configure `SAURON_ALLOWED_ORIGINS` explicitly for deployed web origins.
- Use `SAURON_COMPLIANCE_JURISDICTION_MODE=enforce` with a non-empty `SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST` where required.
- Use `SAURON_COMPLIANCE_SANCTIONS_MODE=enforce` and `SAURON_COMPLIANCE_PEP_MODE=enforce` after wiring a real screening provider.

## Data Tier

SQLite is the local/CI default. Production-like startup requires `SAURON_ACCEPT_SINGLE_NODE_SQLITE=1` to avoid silent HA claims. Before real production, replace or wrap the data tier with:

- managed backups and restore drills,
- migration tooling,
- encryption at rest,
- retention/deletion policy,
- replicated or managed high-availability storage,
- secrets and private key material moved out of ordinary application rows where possible.

For an explicitly accepted single-node deployment, create and validate online
snapshots with `scripts/ops/verify-sqlite-backup.sh`; a release drill must also
restore the produced file into a clean instance. The script exercises SQLite's
online backup API, integrity/foreign-key checks and critical-table presence. It
does not create HA. The partial Postgres adapter remains transitional and the
startup warning deliberately says SQLite is still load-bearing.

Partner private keys must be generated and retained by the partner/HSM. The
production registration API accepts only public material and does not return
or persist a generated private key.

## Proof and authentication boundary

- Production rejects Groth16 even if its compatibility flag is set. The
  RISC Zero verifier accepts pinned native `Composite`/`Succinct` STARK receipts
  from the two reviewed guests in `transparent-zk/`; fake and Groth16-compressed
  receipts fail closed.
- Human login uses the partner/bank-bound Ed25519 challenge flow at
  `/user/auth/challenge` and `/user/auth/finish`. The legacy password-derived
  endpoint is development-only. OPAQUE is needed only if passwords are added
  back as a requirement.
- The Paillier implementation is quarantined in production. It is not a
  production aggregation claim. Transparent local aggregation is the supported
  replacement; threshold HE is a separate future product choice.

## Release Gate

Before a demo or release, run:

```bash
bash scripts/dev/run-all.sh
```

For production-shaped container configuration, use `deploy/docker-compose.prod.yml` as a starting template. It intentionally requires secrets and does not ship development defaults.

At minimum, the gate should include:

- Rust unit tests and clippy,
- Agentic SDK tests,
- ZKP circuit audit,
- issuer/acquirer SDK tests,
- revocation contract tests,
- frontend lint and production builds,
- confidence suite and scripted KYA red-team on a machine that can bind local ports.

## Current Production Boundary

The code now fails closed on the known legacy crypto and policy bypasses, but
commercial release still requires all of the following outside this repo:

- force the agent workload's only network route through the capability gateway
  (separate namespace/VM, deny-by-default firewall and DNS policy);
- real TPM/Nitro end-to-end tests only if marketing the optional hardware tier;
- a managed HA data tier with backups, restore drills and tenant isolation;
- a real OpenTimestamps/chain provider and monitoring of pending/failed anchors;
- an independent cryptographic review and adversarial deployment test.

Without those controls, describe the build as hardened staging software, not
as a guarantee that no agent can run wild.
