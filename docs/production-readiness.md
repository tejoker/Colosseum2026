# Production Readiness

SauronID's production claim should be the cryptographic agent-binding core (per-agent keys, intent leash, per-call signature, JTI / nonce replay protection, screening gates) plus the operational controls around it. Local demo affordances exist, but they must stay out of production-like runtimes.

## Demo vs Production

- `ENV=development` enables demo helpers such as `/dev/register_user`, `/dev/buy_tokens`, `/dev/leash/demo`, `/dev/consent_profile`, and development-only mock ZKP proofs.
- Any non-development `ENV` / `SAURON_ENV` rejects dev helpers and requires explicit secrets.
- Lightning/L402 and Bitcoin anchoring are mock providers unless real providers are explicitly configured.
- Local Hardhat is for demos and tests, not production revocation infrastructure.

## Required Controls

- Set strong random `SAURON_ADMIN_KEY` or `SAURON_ADMIN_KEYS`; production rejects admin keys under 32 bytes.
- Set `SAURON_TOKEN_SECRET`, `SAURON_JWT_SECRET`, and `SAURON_OPRF_SEED` through a secret manager.
- Set `SAURON_DASHBOARD_SESSION_SECRET` and `SAURON_DASHBOARD_OPERATORS` for the signed dashboard session. Use scrypt records for operator passwords; raw SHA-256 records are development-only.
- Keep the dashboard behind TLS and, where appropriate, the optional Caddy HTTP basic-auth defense-in-depth layer.
- For Phase 0+ deployments, set `SAURON_REQUIRE_CALL_SIG=1` to fail-close on missing/invalid per-call signatures (default in non-development runtimes).
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

The system is demo/staging-ready only when all checks pass and the demo is launched with development settings. It is production-ready only after dashboard sessions, strict policy binding, the egress gateway/firewall, external secrets, tenant-safe admin views, untracked runtime DB artifacts, and real payment/anchoring providers are configured.
