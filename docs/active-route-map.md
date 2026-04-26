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

Merkle roots are anchored through `SAURON_BITCOIN_ANCHOR_PROVIDER=mock` by default. The mock creates a Bitcoin OP_RETURN-style payload and records it in `bitcoin_merkle_anchors`; it does not broadcast and does not spend BTC. Solana anchoring is no longer part of the active backend.

## Supporting Proof and Owner Routes

- `POST /oprf`
- `POST /zkp/proof_material`
- `POST /user/auth`
- `GET /user/credential`
- `GET /user/consents`
- `DELETE /user/consent/{request_id}`

## Archived Product Paths

KYC, CAMARA, card login, phone verification, and consent-popup flows are archived under `legacy/` and are not part of the default runtime.
