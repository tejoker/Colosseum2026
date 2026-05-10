# SauronID

**The cryptographic agent-binding layer for AI deployments.**

Wherever your AI agents act on behalf of humans or other systems, SauronID sits in the path and turns every call into a signed, replay-protected, intent-leashed, audit-anchored event. An agent that has been registered with SauronID cannot:

- replay a captured token,
- mutate a request body after signing,
- act outside its declared intent,
- silently flip its system prompt or tool list,
- escalate scope across delegation,
- evade the audit log,
- act after revocation.

These are not aspirational claims. They are tested by the **16-attack empirical suite** (`docs/empirical-comparison.md`) which runs against a live server and reports `16/16 blocked` in fail-closed mode. Anyone can re-run it.

## What SauronID is, and what it is not

| | |
|---|---|
| **Is** | A self-hostable HTTP service in Rust + a TS/Python client. Every protected endpoint a registered agent calls verifies: A-JWT signature, intent-leash, per-call DPoP-style body signature, single-use nonce, single-use JTI, agent-runtime config digest, rate limits. Every agent action is merkle-anchored to Bitcoin (OpenTimestamps) and Solana (Memo) for tamper-evident audit. |
| **Is not** | A user-authentication system. SauronID does not handle human SSO/SAML/social-login. Plug it next to your existing user auth (or none) — the human authorisation flow is independent. SauronID is purely about **the agent layer**: from the moment an AI agent is allowed to act, until it acts. |

If your AI agents call internal APIs, your customers' APIs, third-party APIs, or each other — that traffic is what SauronID binds.

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
- Vault Transit envelope encryption for `jwt_secret` / `token_secret` / `oprf_seed` / `admin_key`.
- AWS KMS adapter (replaces stub).
- AWS Nitro attestation chain validation (replaces stub).
- Telemetry: `tracing` (JSON or pretty), Prometheus `/metrics`, structured logs.
- Background GC for 5 expirable tables.
- Forward proxy for outbound agent egress with intent-allowlist enforcement.
- Python client (`clients/python/sauronid_client/`) with LangChain, OpenAI Assistants, and Anthropic Computer Use adapters.
- TypeScript client (`agentic/src/`) with the same primitives.
- Postgres backend opt-in (3 modules ported; 9 still on rusqlite — incremental).

### Partial — works but operator must complete

- **Postgres swap**: 3 modules ported (`agent_call_nonces`, `risk_rate_counters`, `ajwt_used_jtis`). 9 modules still rusqlite. Single-node SQLite is the default; switch via `SAURON_DB_BACKEND=postgres` for the ported modules.
- **OpenTimestamps confirmation latency**: receipts are submitted instantly to public calendars; **Bitcoin block inclusion takes ~1 hour**. Solana memo finalisation is ~30 s. Operators with stricter timing pick the Solana path or run their own calendar.
- **ZKP issuer / KYC consent / bank-KYC ingest**: feature-flagged off by default. Available behind `SAURON_DISABLE_*=0` for legacy deployments. SauronID does NOT ship a sanctions/PEP screening provider — wire your own data into `compliance_screening`.

### Cannot do — out of scope by design

- Replace your IdP, SSO, or human-auth system. SauronID does not authenticate humans.
- Detect a compromised agent host without hardware attestation. Process-memory access defeats every signature-based system. Mitigation: hardware-backed PoP keys (TPM2 / AWS Nitro / Apple Secure Enclave / SEV-SNP).
- Multi-region without operator effort. Single-binary deploys are vertical scaling only.
- Pass SOC2 / ISO 27001 audit. No audit performed yet.

## Quickstart (one command, 60 seconds)

```bash
git clone https://github.com/your-org/sauronid && cd sauronid
./quickstart.sh
```

The script: builds the Rust core, builds the TS clients, starts the server in dev mode, seeds clients/users, and runs the 9-scenario invariant suite + the 16-attack empirical suite. Both must pass green at the end.

To run in fail-closed (production-like) mode:

```bash
SAURON_REQUIRE_CALL_SIG=1 ./quickstart.sh
```

To deploy in production: see [docs/operations.md](docs/operations.md).

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
- SauronID's score: **16/16 blocked**.
- Comparison vs DPoP (RFC 9449), HTTP Message Signatures (RFC 9421), GNAP (RFC 9635), Anthropic MCP, Auth0 Agent Identities, AWS IAM Roles for Agents.
- Latency benchmark: p50=2 ms, p99=8 ms at conc=1; p50=13 ms, p99=25 ms at conc=10.

To reproduce the empirical claim:

```bash
SAURON_REQUIRE_CALL_SIG=1 ./quickstart.sh
# at the end, the empirical suite reports "16/16 pass"
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

## Critical files

- Core service: [`core/`](core/) — Rust, axum, ~21k lines.
- TypeScript client: [`agentic/`](agentic/) — `signCall`, `register`, `popKeys`.
- Python client: [`clients/python/sauronid_client/`](clients/python/sauronid_client/) — LangChain + OpenAI + Anthropic adapters.
- Empirical attack suite: [`kya-redteam/`](kya-redteam/) — 9 invariant scenarios + 16-attack empirical suite.
- Custom Solana program: [`contracts/sauron_ledger/`](contracts/sauron_ledger/) — Anchor program (optional; default uses Solana Memo).
- Operations: [`docs/operations.md`](docs/operations.md) — every env var, every deploy step.
- Threat model: [`docs/threat-model.md`](docs/threat-model.md) — what we protect against, what we don't.
- Empirical comparison: [`docs/empirical-comparison.md`](docs/empirical-comparison.md) — vs DPoP / GNAP / MCP / Auth0 / AWS / Cloudflare.

## Production deployment checklist

```bash
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
SAURON_VAULT_TRANSIT_ENABLED=1                   # secrets in Vault, not env
SAURON_REQUIRE_AGENT_TYPE=1                      # legacy fallback rejected
SAURON_DB_BACKEND=postgres                       # for ported modules
DATABASE_URL=postgres://...
```

Full guide: [docs/operations.md](docs/operations.md).

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
