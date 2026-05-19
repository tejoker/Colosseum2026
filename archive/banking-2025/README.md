# Archive — Banking 2025

Retired product paths from the pre-pivot bank-KYC era. Kept for git continuity
and reference only. Not part of the active SauronID architecture and not wired
into the default docker compose stack or `scripts/dev/start.sh`.

- `KYC/`: archived Python KYC adapter (FastAPI on :8000). Run manually only.
- `camara/`: archived CAMARA / Mobile Connect / card-login package.
- `contracts/`: archived Solana Anchor Merkle-root ledger.

Do not wire these services into the default stack unless the product explicitly
reintroduces KYC or phone-possession onboarding.
