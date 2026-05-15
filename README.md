# SauronID

**The cryptographic agent-binding layer for AI deployments.**

## Why this matters

An AI agent that gets compromised at runtime — by prompt injection, a tampered system prompt, a swapped tool definition, a stolen token — can do real damage in a few HTTP calls. Replay a captured token, mutate the request body after signing, escalate scope through delegation, drift its config without anyone noticing.

**Without SauronID**, an attacker who pwns your agent can do all of the above. **With SauronID**, every one of those produces an HTTP 401 in under 5 ms, on every request. There is no "trust the agent runtime" assumption: each call is independently re-verified against a binding that the operator cannot forge.

The [16-attack empirical suite](redteam/) covers this in two layers: **10/16 attacks (A1–A10) are dynamically executed against a live server, all blocked**; **6/16 attacks (A11–A16) are verified by source-code review** against canonical patterns (atomic `UPDATE ... WHERE` TOCTOU, constant-time HMAC compares, `UNIQUE` constraints on every consume table). Dynamic harness for A11–A16 is tracked in the redteam roadmap. Anyone can re-run the dynamic layer (`npx tsx redteam/src/scenarios/empirical-suite.ts`).

Default mode is **advisory** (logs violations but accepts). Set `SAURON_REQUIRE_CALL_SIG=1` for **fail-closed** enforcement. All numbers below assume fail-closed unless stated.

## What an agent under SauronID cannot do

- replay a captured A-JWT,
- mutate a request body after signing it,
- act outside its declared `intent`,
- silently swap its system prompt, tool list, or model id,
- escalate scope across delegation (parent → child),
- evade the merkle-anchored audit log,
- act after revocation.

## What SauronID is, and what it is not

| | |
|---|---|
| **Is** | A self-hostable HTTP service in Rust + a TS/Python client. Every protected endpoint a registered agent calls verifies: A-JWT signature, intent-leash, per-call DPoP-style body signature, single-use nonce, single-use JTI, agent-runtime config digest, rate limits. Every agent action is merkle-anchored to Bitcoin (OpenTimestamps) and Solana (Memo) for tamper-evident audit. |
| **Is not** | A user-authentication system. SauronID does not handle human SSO/SAML/social-login. Plug it next to your existing user auth (or none) — the human authorisation flow is independent. SauronID is purely about **the agent layer**: from the moment an AI agent is allowed to act, until it acts. |

If your AI agents call internal APIs, your customers' APIs, third-party APIs, or each other — that traffic is what SauronID binds.

## Trust model

Be honest about who you have to trust.

- **PoP keys are derived server-side** as `SHA256(jwt_secret | agent_id | human_key_image | agent_checksum)`. The operator who controls `jwt_secret` can derive any agent's PoP key. The trust assumption is therefore: **the operator of the SauronID server is trusted**. Compromise of `jwt_secret` is equivalent to compromise of every agent identity in the deployment. Protect it accordingly (Vault Transit / KMS wrapping is on the roadmap — see Partial section).
- **Hardware-bound PoP keys** (TPM2, AWS Nitro, Apple Secure Enclave, SEV-SNP) would remove this trust assumption by binding the private key material to hardware the operator does not directly hold. The attestation enum and the operator-rooted `ed25519_self` verifier ship today; the hardware verifiers are roadmap (see Partial).
- **Agent runtime trust** is bounded but not eliminated. SauronID detects config drift, replay, body mutation, scope escalation, and post-revocation use. It does **not** detect an attacker with full process-memory access on the agent host — only hardware attestation does that.
- M1 of TPM2 roadmap shipped: server-derived PoP is now explicit and refused in production by default; TPM2 quote endpoint accepts well-formed payloads but full verification (vendor cert-chain walker) is M2. See [docs/roadmap.md](docs/roadmap.md) Plan 1.
- M2 shipped: TPM2 quote parsing + AIK signature verification + cert-chain walker. Operators supply vendor roots via `SAURON_TPM2_VENDOR_ROOTS_DIR`. M3 (cutover from server-derived keys) still pending.

## What ships, what's partial, what doesn't yet exist

Honest table. Re-verifiable from the source.

### Fully shipped — verified by the 16-attack empirical suite

- Per-agent Ed25519 PoP keys with mandatory hardware-attestation slot.
- A-JWT (intent + checksum + delegation depth) with single-use JTI.
- DPoP-style per-call signature over `method | path | sha256(body) | timestamp | nonce`.
- Server-computed agent checksum from typed `agent_type` + `checksum_inputs`. Operators cannot supply a fake checksum.
- Per-call `x-sauron-agent-config-digest` header check: agent runtime cannot drift from registered config without rejecting on every call.
- Atomic single-use TOCTOU patterns on every consume table (consent, payment, credential, bank nonce, lightning, call-nonce, JTI).
- Constant-time HMAC compares (no timing oracles).
- CORS hard-fail on empty origins (no permissive fallback).
- Sliding-window rate limits per agent + per human.
- Merkle commitment of agent action receipts → Bitcoin (OpenTimestamps) + Solana (Memo) → externally verifiable via `ots verify` and Solana Explorer.
- Operator-rooted `ed25519_self` hardware-attestation verifier (signed runtime measurements with an operator-held Ed25519 key, e.g. HSM / YubiKey).
- Telemetry: `tracing` (JSON or pretty), Prometheus `/metrics`, structured logs.
- Background GC for 5 expirable tables.
- Egress reporting endpoint where agents voluntarily POST signed records of their outbound calls. Intent-allowlist enforcement is operator-side (separate egress controller or service mesh). SauronID provides the auditable log and per-call signature verification; it does not proxy traffic in-band.
- Python client (`clients/python/sauronid_client/`) with LangChain, OpenAI Assistants, and Anthropic Computer Use adapters.
- TypeScript client (`agentic/src/`) with the same primitives.
- Postgres backend opt-in (3 modules ported; 9 still on rusqlite — incremental).

### Partial — works but operator must complete

- **Postgres swap**: 3 modules ported (`agent_call_nonces`, `risk_rate_counters`, `ajwt_used_jtis`). 9 modules still rusqlite. Single-node SQLite is the default; switch via `SAURON_DB_BACKEND=postgres` for the ported modules.
- **OpenTimestamps confirmation latency**: receipts are submitted instantly to public calendars; **Bitcoin block inclusion takes ~1 hour**. Solana memo finalisation is ~30 s. Dashboard surfaces three honest states per batch (ADR-001): Solana-confirmed (≤30 s), BTC-pending (≤1 h), Dually anchored. No single false "anchored" summary — both chains are reported independently on `/admin/anchor/batches` and the `/anchors` console page. Operators with stricter timing pick the Solana path or run their own calendar.
- **ZKP issuer / KYC consent / bank-KYC ingest**: feature-flagged off by default. Available behind `SAURON_DISABLE_*=0` for legacy deployments. SauronID does NOT ship a sanctions/PEP screening provider — wire your own data into `compliance_screening`.
- **Vault Transit envelope encryption**: the `secret_provider` abstraction is shipped and resolves `<NAME>_WRAPPED` env vars through `POST /v1/transit/decrypt/<key>` when `SAURON_VAULT_TRANSIT_ENABLED=1`. The call path is **not yet wired into server init** for `jwt_secret` / `token_secret` / `oprf_seed` / `admin_key` — today those secrets are still loaded from plain env vars (or sit unencrypted in the DB for derived keys). Roadmap: wire the Vault path through `core/src/secret_provider.rs` into init before the first production customer. Source: [`core/src/secret_provider.rs`](core/src/secret_provider.rs).
- **AWS KMS adapter**: not implemented. `resolve_via_kms()` in [`core/src/secret_provider.rs`](core/src/secret_provider.rs) returns `BackendUnavailable("AWS KMS adapter not yet wired (Phase 1B)")`. Use the Vault Transit path once wired, or supply your own adapter.
- **Hardware attestation beyond `ed25519_self`**: the `AttestationKind` enum recognises `tpm2_quote`, `sgx_quote`, `sev_snp`, `arm_cca`, `nitro_enclave`, `apple_secure`, but every verifier except `ed25519_self` returns `AttestationError::NotImplemented` today. Source: [`core/src/attestation.rs`](core/src/attestation.rs). To deploy with hardware-rooted PoP, either use the operator-signed `ed25519_self` path (works today) or supply a verifier for your target platform. AWS Nitro chain validation is roadmap, not shipped.

### Cannot do — out of scope by design

- Replace your IdP, SSO, or human-auth system. SauronID does not authenticate humans.
- Detect a compromised agent host without hardware attestation. Process-memory access defeats every signature-based system. Mitigation: hardware-backed PoP keys (TPM2 / AWS Nitro / Apple Secure Enclave / SEV-SNP).
- Multi-region without operator effort. Single-binary deploys are vertical scaling only.
- Pass SOC2 / ISO 27001 audit. No audit performed yet.

## Quickstart (one command, 60 seconds)

```bash
git clone https://github.com/tejoker/Colosseum2026 sauronid && cd sauronid
./quickstart.sh
```

The script: builds the Rust core, builds the TS clients, starts the server in dev mode, seeds clients/users, and runs the 9-scenario invariant suite + the empirical suite (10 attacks dynamic, 6 attacks via source-code review). Both must pass green at the end.

By default the server runs in **advisory** mode (logs call-signature violations but accepts them). To run in **fail-closed** (production-like) enforcement mode:

```bash
SAURON_REQUIRE_CALL_SIG=1 ./quickstart.sh
```

The "16/16 blocked" empirical claim assumes this flag is set.

For a full local demo (core + analytics shim + branded Next.js dashboard) in one shot:

```bash
./launch.sh
# core      → http://127.0.0.1:3001
# analytics → http://127.0.0.1:8002
# dashboard → http://127.0.0.1:3000   (Mandate Console)
```

To deploy in production: see [docs/operations.md](docs/operations.md).

## Mandate Console — the web dashboard

A branded Next.js console at `sauron-dashboard/` reads only live data from the running core (no parquet, no fixtures). Six routes:

| Route | What it shows |
|---|---|
| `/` Overview | Active agents, PoP-bound count, daily action receipts (90d gradient line), anchor pipeline doughnut, ring memberships |
| `/agents` | Agent registry with PoP / config-digest / action + egress counters, filter strip (TOTAL / ACTIVE / REVOKED / NO·POP) |
| `/anchors` | Anchor batches, BTC OTS upgraded vs pending, Solana confirmed vs unconfirmed, recent receipts |
| `/clients` | Partner-site ring members, search + type filter |
| `/users` | OPRF key-image registry (humans), nationality breakdown |
| `/requests` | Append-only activity log, polled every 5 s |

Visual identity is in [`BRANDING.md`](BRANDING.md): dark navy canvas (`#06090F`), Sauron Blue / Ice Blue / Cyan, Instrument Serif display, Space Mono structural labels, Satoshi UI body. Investor pitch deck: [`SauronID_Pitch_Deck.pdf`](SauronID_Pitch_Deck.pdf).

## End-to-end simulation

Once the stack is up (`./launch.sh`), four scripts under [`scripts/`](scripts/) drive the full flow:

```bash
# Register N agents per seeded human + signed egress logs
python3 scripts/simulate_agents.py

# Full real action-receipt flow:
#   user_auth → agent_register (ring + PoP + intent) → A-JWT → action/challenge
#   → agent-action-tool sign-challenge → payment_authorize (per-call sig + PoP JWS)
#   → POST /admin/anchor/agent-actions/run
# Each iteration writes a row into agent_action_receipts and triggers a real
# Bitcoin OTS anchor (and Solana when SAURON_SOLANA_ENABLED=1).
python3 scripts/simulate_real_actions.py --n-actions 2

# Solana devnet keypair generation + airdrop with multi-RPC retry
python3 scripts/solana_devnet_setup.py

# Independent Solana wire-format audit (re-implements the Rust transaction
# encoder in Python and posts to devnet)
python3 scripts/solana_audit.py
```

After `simulate_real_actions.py`, the dashboard's Anchors page populates with real `agent_action_receipts`, the BTC anchor count advances, and (with Solana enabled) so does the Solana count.

## Integrate with your AI agent

```python
from sauronid_client import SauronIDClient, register_llm_agent

# Register an agent (server computes checksum from typed config)
client = SauronIDClient(base_url="https://sauronid.your-company.internal")
agent = register_llm_agent(
    client,
    user_session=...,
    model_id="claude-opus-4-7",
    system_prompt=open("prompts/research_agent.md").read(),
    tools=["search", "fetch"],
)

# Every call routed through `agent.call(...)` is signed + leashed + audit-anchored
result = agent.call("/internal/api/search", {"query": "..."})
```

LangChain wrapper, OpenAI Assistants wrapper, and Anthropic Computer Use wrapper in [`clients/python/sauronid_client/`](clients/python/sauronid_client/).

For TypeScript: [`agentic/src/`](agentic/src/).

## Empirical proof

Every claim above has a runnable test. See [docs/empirical-comparison.md](docs/empirical-comparison.md) for:

- 16 concrete attacks against AI-agent binding systems.
- SauronID's score in fail-closed mode: **10/16 blocked via live dynamic execution (A1–A10)**, **6/16 verified via source-code review against canonical patterns (A11–A16)** — atomic `UPDATE ... WHERE` for TOCTOU, constant-time HMAC compares, `UNIQUE` constraints on consume tables. Dynamic harness for A11–A16 is on the redteam roadmap.
- Comparison vs DPoP (RFC 9449), HTTP Message Signatures (RFC 9421), GNAP (RFC 9635), Anthropic MCP, Auth0 Agent Identities, AWS IAM Roles for Agents.
- Latency benchmark: p50=2 ms, p99=8 ms at conc=1; p50=13 ms, p99=25 ms at conc=10.

To reproduce the empirical claim (requires fail-closed mode):

```bash
SAURON_REQUIRE_CALL_SIG=1 ./quickstart.sh
# at the end, the dynamic empirical suite reports "10/10 blocked" for A1–A10.
# A11–A16 are validated by reading core/src for the canonical patterns.
```

## Architecture (high level)

```
┌────────────┐   register   ┌──────────────────────────┐
│   Human    ├─────────────▶│   SauronID Core          │
│ (operator) │              │   (Rust, axum, sqlite/pg)│
└────────────┘              │                          │
                            │  ┌────────────────────┐  │
┌────────────┐              │  │ /agent/register    │  │
│ AI Agent   │   per-call   │  │ /agent/{...}       │  │
│  (Python /  ├──signed──▶ │  │ /agent/egress/log  │  │
│   TS / etc) │  request    │  │ /admin/anchor/...  │  │
└────────────┘              │  └────────────────────┘  │
                            │                          │
                            │  Background workers:     │
                            │   • OTS upgrader (BTC)   │
                            │   • Solana confirmer     │
                            │   • Action anchor batch  │
                            │   • GC for expirable     │
                            └──────────┬───────────────┘
                                       │
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                   Bitcoin (OTS)   Solana       Postgres /
                   tamper-evident  Memo Tx      SQLite
                   audit anchor    audit anchor   storage
```

## Repo layout — what is current, what is historical

The repo carries a previous-life of bank-KYC code under `legacy/` and adjacent
fixtures. The active SauronID surface is a focused subset.

**Current SauronID code** (review these):

```
core/                  Rust axum service (SauronID core, ~14k lines core Rust)
sauron-dashboard/      Next.js Mandate Console
clients/python/        Python adapter (SignedAgent + LLM wrappers)
agentic/               TypeScript adapter
redteam/               16-attack empirical suite + 18-attack Tavily fuzzer
scripts/               simulate_real_actions.py, solana_audit.py, etc.
contracts/             Solana Anchor program (sauron_ledger)
docs/                  threat-model, operations, production-readiness
BRANDING.md            Visual identity (Mandate Console)
SauronID_Pitch_Deck.pdf
```

**Historical / not part of the SauronID product surface** (do not depend on):

```
legacy/KYC/            Old bank-KYC ingest. Feature-flagged off by default.
data/sauron/data/*.csv Banking-era persona/expense fixtures. Unused.
anomaly-engine/        Old anomaly pipeline. Unused.
partner-portal/        Bank/retail UI. Demo-quality, not core to SauronID.
subgraph/              Subgraph schema scaffolding. Inactive.
```

These exist for git history continuity and may be removed in a future cleanup.

## Critical files

- Core service: [`core/`](core/) — Rust, axum, ~14k lines core Rust (count: `find core/src -name '*.rs' | xargs wc -l`).
- Mandate Console: [`sauron-dashboard/`](sauron-dashboard/) — Next.js + Chart.js, dark branded UI reading live core data only.
- Brand system: [`BRANDING.md`](BRANDING.md), pitch deck at [`SauronID_Pitch_Deck.pdf`](SauronID_Pitch_Deck.pdf), eye logo at [`logo.svg`](logo.svg).
- TypeScript client: [`agentic/`](agentic/) — `signCall`, `register`, `popKeys`.
- Python client: [`clients/python/sauronid_client/`](clients/python/sauronid_client/) — LangChain + OpenAI + Anthropic adapters.
- Empirical attack suite: [`redteam/`](redteam/) — 9 invariant scenarios + 16-attack empirical suite + 18-attack Tavily fuzzer.
- Simulation + audit scripts: [`scripts/`](scripts/) — real action receipts, agent stress, Solana devnet setup + wire audit.
- Custom Solana program: [`contracts/sauron_ledger/`](contracts/sauron_ledger/) — Anchor program (optional; default uses Solana Memo).
- Operations: [`docs/operations.md`](docs/operations.md) — every env var, every deploy step.
- Threat model: [`docs/threat-model.md`](docs/threat-model.md) — what we protect against, what we don't.
- Empirical comparison: [`docs/empirical-comparison.md`](docs/empirical-comparison.md) — vs DPoP / GNAP / MCP / Auth0 / AWS / Cloudflare.

## Production deployment checklist

```bash
# Deploy behind a TLS-terminating reverse proxy. The core binds plain HTTP.
# See docs/operations.md "TLS termination" for requirements.
ENV=production
SAURON_ADMIN_KEY=$(openssl rand -hex 32)
SAURON_TOKEN_SECRET=$(openssl rand -hex 32)
SAURON_JWT_SECRET=$(openssl rand -hex 32)
SAURON_OPRF_SEED=$(openssl rand -hex 32)
SAURON_ALLOWED_ORIGINS=https://your-edge.example.com
SAURON_REQUIRE_CALL_SIG=1                        # fail-closed
SAURON_DISABLE_BANK_KYC=1                        # off unless you need legacy bank flow
SAURON_DISABLE_USER_KYC=1                        # off unless you need consent UI
SAURON_DISABLE_ZKP=1                             # off unless you need ZKP credentials
SAURON_DISABLE_COMPLIANCE=1                      # off unless you wire screening provider
SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps    # real BTC anchoring
SAURON_SOLANA_ENABLED=1                          # dual-anchor on Solana
SAURON_SOLANA_RPC_URL=https://api.devnet.solana.com   # mainnet later
SAURON_SOLANA_KEYPAIR_PATH=/etc/sauronid/sol-key.json
SAURON_VAULT_TRANSIT_ENABLED=1                   # secret_provider abstraction; init-path wiring is roadmap (see Partial)
SAURON_REQUIRE_AGENT_TYPE=1                      # legacy fallback rejected
SAURON_DB_BACKEND=postgres                       # for ported modules
DATABASE_URL=postgres://...
```

Full guide: [docs/operations.md](docs/operations.md).

## Repo provenance

This codebase was started during the **Solana Colosseum 2026 hackathon**, building on a prior **2025 hackathon prototype** (which is preserved under `legacy/` for git-history continuity). Active development continues post-hackathon. Reviewers and auditors should keep this provenance in mind: some surfaces are production-grade and battle-tested, others are hackathon-grade and explicitly flagged in the "Partial" and "Cannot do" sections above. The boundary is the boundary — don't infer maturity from polish.

## Contributing / development

```bash
# Run all tests + 16-attack empirical
make verify

# Just the empirical suite
make empirical

# Cold rebuild + re-run
make clean && ./quickstart.sh
```

The full session log of how this was built (multi-week, agent-driven) is intentionally not in the repo. The codebase is the spec.
