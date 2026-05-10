# Active Route Map

The active SauronID product is agent binding and bounded authorization. Routes not listed here are legacy or support-only.

## Admin

- `GET /admin/stats`
- `GET /admin/clients`
- `POST /admin/clients`
- `GET /admin/users`
- `GET /admin/requests`
- `GET /admin/site/{name}/users`
- `GET /admin/site/{name}/zkp_proofs`

## Agent Binding

- `POST /agent/register`
- `POST /agent/verify`
- `POST /agent/pop/challenge`
- `GET /agent/list/{human_key_image}`
- `GET /agent/{agent_id}`
- `DELETE /agent/{agent_id}`

## Agent Bounding

- `POST /policy/authorize`
- `POST /agent/payment/authorize`
- `POST /merchant/payment/consume`
- `POST /lightning/l402/challenge`
- `POST /lightning/l402/settle`
- `GET /paid/agent-score/{agent_id}`
- `POST /agent/payment/nonexistence/material`
- `POST /agent/payment/nonexistence/verify`

`/lightning/l402/*` uses `SAURON_LIGHTNING_PROVIDER=mock` by default. This is the only implemented provider and is intentionally no-cost for tests: invoices, macaroons, and preimages are generated locally and settlement only updates SQLite.

## Bitcoin Anchoring

Merkle roots are anchored through `SAURON_BITCOIN_ANCHOR_PROVIDER=mock` by default. The mock creates a Bitcoin OP_RETURN-style payload and records it in `bitcoin_merkle_anchors`; it does not broadcast and does not spend BTC.

## Supporting Proof and Owner Routes

- `POST /oprf`
- `POST /zkp/proof_material`
- `POST /user/auth`
- `GET /user/credential`
- `GET /user/consents`
- `DELETE /user/consent/{request_id}`

## Development-only Demo Routes

These routes are rejected outside development-like runtimes:

- `POST /dev/register_user`
- `POST /dev/buy_tokens`
- `POST /dev/leash/demo`
- `POST /dev/consent_profile`

## Archived product paths

- **Python KYC adapter** → `legacy/KYC/` (not started by default compose / `start.sh`).
- **CAMARA, card login, phone verification, consent-popup UIs** → see `legacy/` (e.g. `legacy/camara/`, archived portal flows per `legacy/README.md`).

Rust core still exposes `/kyc/*` and `/agent/kyc/*` routes for **consent + retrieval** against the in-process DB; those are **not** the archived Python service. If you want those removed too, that is a separate core refactor.
