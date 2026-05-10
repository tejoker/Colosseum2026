# Legacy Components

This folder keeps retired product paths available without making them part of the active SauronID architecture.

- `KYC/`: archived Python KYC adapter (FastAPI on :8000). Run manually if you need the old upsert/lookup API; it is **not** part of default `docker compose` or `start.sh`.
- `camara/`: archived CAMARA/Mobile Connect/card-login package.
- `contracts/sauron_ledger/`: archived Solana Anchor Merkle-root ledger.
- `partner-portal/app/`: archived KYC, bank, retail, consent, and SDK demo pages.
- `core/tests/`: archived KYC/KYA consent E2E scripts.

Do not wire these services into the default compose stack or active startup script unless the product explicitly reintroduces KYC or phone-possession onboarding.
