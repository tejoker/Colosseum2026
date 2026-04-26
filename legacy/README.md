# Legacy Components

This folder keeps retired product paths available without making them part of the active SauronID architecture.

- `KYC/`: archived Python KYC adapter service.
- `camara/`: archived CAMARA/Mobile Connect/card-login package.
- `partner-portal/app/`: archived KYC, bank, retail, consent, and SDK demo pages.
- `core/tests/`: archived KYC/KYA consent E2E scripts.

Do not wire these services into the default compose stack or active startup script unless the product explicitly reintroduces KYC or phone-possession onboarding.
