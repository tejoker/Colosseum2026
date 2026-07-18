# SauronID

**A fail-closed authorization and verifiable-audit boundary for AI agents.**

## Why this matters

An AI agent compromised by prompt injection or hostile tools can do real damage
through otherwise valid credentials. SauronID puts an independently enforced
gateway in front of those actions: tenant-bound sessions, exact request
signatures, one-use capabilities, server-side policy evaluation, disclosure
contracts, byte and rate caps, and a tamper-evident action log.

This is containment, not a proof that an agent is benevolent. A valid but overly
broad policy still authorizes harm, and traffic that can bypass the gateway is
outside its control. Production therefore fails closed and requires the
deployment network policy in [`deploy/kubernetes/agent-network-isolation.yaml`](deploy/kubernetes/agent-network-isolation.yaml)
or an equivalent deny-by-default egress boundary.

Compliance statements are proved by the transparent RISC Zero STARK guests in
[`transparent-zk/`](transparent-zk/). They require no per-circuit setup ceremony;
customers verify receipts locally against published image IDs. The proof
certifies computation over the complete externally anchored receipt batch. It
cannot certify that a real-world event was truthful or that an event which
never entered the protected path occurred.

## What an agent under SauronID cannot do

- replay a captured A-JWT,
- mutate a request body after signing it,
- act outside its declared `intent`,
- silently swap its system prompt, tool list, or model id,
- escalate scope across delegation (parent → child),
- change an already finalized and externally anchored receipt batch without detection,
- act after revocation.

Those guarantees apply only to protected calls that cannot route around the
gateway and only within the limits encoded by the operator's policy.

## What SauronID is, and what it is not

| | |
|---|---|
| **Is** | A self-hostable Rust authorization gateway with TS, Python, and Go clients. Protected calls bind tenant, method, path, audience, query, body digest, timestamp, nonce, intent, runtime configuration, and one-use credentials. Finalized action batches can back native transparent STARK statements and external timestamp proofs. |
| **Is not** | A sandbox, a complete IdP, an oracle for human intent, or evidence that source data is true. It includes tenant-bound passwordless Ed25519 sessions, but SSO/SAML/social login remains an integration with the customer's IdP. |

If your AI agents call internal APIs, your customers' APIs, third-party APIs, or each other — that traffic is what SauronID binds.

## Trust model

Be honest about who you have to trust.

- Production agents register client-generated Ed25519 proof-of-possession keys;
  server-derived PoP is refused. Hardware attestation is not required for the
  authorization or STARK proof path.
- TPM/Nitro can be enabled as an optional claim about where a key or program
  executed. That claim adds vendor/hardware assumptions and requires real-device
  release evidence; it is not a consequence of Groth16 and does not make an
  authorized policy safe.
- The STARK prover and agent process are untrusted. Verifiers still rely on the
  published guest source/image ID, RISC Zero's proof-system assumptions,
  collision-resistant hashing, and correct verifier software. This is
  cryptographic verification, not unconditional mathematics.
- A hostile process holding a valid agent key can request anything its current
  policy permits. The independent gateway, one-use capabilities, rate/amount
  caps, response-disclosure rules, and network isolation limit that authority;
  they cannot infer whether an allowed action is wise.
- Canonical trust boundaries and remaining impossibility results are maintained
  in [`docs/crypto-migration-boundary.md`](docs/crypto-migration-boundary.md).

## What ships, what's partial, what doesn't yet exist

Honest table. Re-verifiable from the source.

### Implemented security path

- Client-generated per-agent Ed25519 PoP keys; optional hardware-attestation
  evidence is challenge- and key-bound when explicitly enabled.
- A-JWT (intent + checksum + delegation depth) with single-use JTI.
- Versioned per-call signature over tenant, method, path, canonical query,
  audience, body digest, timestamp, nonce, JTI, and runtime configuration.
- Server-computed agent checksum from typed `agent_type` + `checksum_inputs`. Operators cannot supply a fake checksum.
- Per-call `x-sauron-agent-config-digest` header check: agent runtime cannot drift from registered config without rejecting on every call.
- Atomic single-use TOCTOU patterns on every consume table (consent, payment, credential, bank nonce, lightning, call-nonce, JTI).
- Constant-time HMAC compares (no timing oracles).
- CORS hard-fail on empty origins (no permissive fallback).
- Sliding-window rate limits per agent + per human.
- Complete v2 Merkle commitment of action receipts → Bitcoin
  (OpenTimestamps) + Solana (Memo), with authoritative tenant-scoped proof
  checkpoints.
- Native RISC Zero `Succinct`/`Composite` STARK verification for stats and
  action-policy statements. Fake, Groth16-compressed, unknown, wrong-program,
  wrong-tenant, and wrong-checkpoint receipts fail closed.
- Tenant-bound passwordless user challenge/response using an Ed25519 key, with
  short-lived one-use challenges and signed sessions.
- Telemetry: `tracing` (JSON or pretty), Prometheus `/metrics`, structured logs.
- Background GC for 5 expirable tables.
- In-band egress capability gateway: exact host/method/path constraints,
  request/response disclosure modes, allowed-header and byte caps, DNS/SSRF
  checks, redirect refusal, credential brokerage, one-use capabilities, and
  rate buckets. Production rejects bare-host policies.
- Python client (`clients/python/sauronid_client/`) with LangChain, OpenAI Assistants, and Anthropic Computer Use adapters.
- TypeScript client (`agentic/src/`) with the same primitives.
- SQLite online-backup verification and restore-integrity tooling for the
  supported single-node topology.

### Partial — works but operator must complete

- **Database topology**: SQLite remains load-bearing even when the partial
  Postgres paths are enabled. Production startup requires explicit acceptance
  of the single-node topology. There is no honest HA/failover/multi-region
  claim yet; use a dedicated node and perform the documented restore drill.
- **OpenTimestamps confirmation latency**: receipts are submitted instantly to public calendars; **Bitcoin block inclusion takes ~1 hour**. Solana memo finalisation is ~30 s. Dashboard surfaces three honest states per batch (ADR-001): Solana-confirmed (≤30 s), BTC-pending (≤1 h), Dually anchored. No single false "anchored" summary — both chains are reported independently on `/admin/anchor/batches` and the `/anchors` console page. Operators with stricter timing pick the Solana path or run their own calendar.
- **ZKP issuer / KYC consent / bank-KYC ingest**: feature-flagged off by default. Available behind `SAURON_DISABLE_*=0` for legacy deployments. SauronID does NOT ship a sanctions/PEP screening provider — wire your own data into `compliance_screening`.
- **External key custody**: production secret resolution and external partner-key
  custody are fail-closed configuration obligations. Vault loopback behavior is
  covered by tests, but the deployment must supply, authorize, rotate, and
  recover its real secret backend.
- **Optional hardware tier**: TPM2 and Nitro verification code exists, but no
  hardware-tier claim is release-ready without real-device end-to-end evidence
  for the exact production image and vendor roots.

### Cannot do — out of scope by design

- Prove that an unobserved real-world event happened or that submitted source
  data was truthful. It proves computation and completeness relative to the
  finalized protected receipt batch.
- Determine that every syntactically valid encoded payload is semantically free
  of sensitive data.
- Prevent damage which an operator's policy deliberately or accidentally
  authorizes.
- Protect calls which can bypass the gateway at the network layer.
- Multi-region without operator effort. Single-binary deploys are vertical scaling only.
- Prove the absence of unknown vulnerabilities or replace an independent
  cryptographic review, penetration test, and deployment audit.

## Quickstart (one command, 60 seconds)

```bash
git clone https://github.com/tejoker/Colosseum2026 sauronid && cd sauronid
./scripts/dev/quickstart.sh
```

The script: builds the Rust core, builds the TS clients, starts the server in dev mode, seeds clients/users, and runs the 9-scenario invariant suite + the empirical suite (10 attacks dynamic, 6 attacks via source-code review). Both must pass green at the end.

By default the server runs in **advisory** mode (logs call-signature violations but accepts them). To run in **fail-closed** (production-like) enforcement mode:

```bash
SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh
```

The "16/16 blocked" empirical claim assumes this flag is set.

For a full local demo (core + analytics shim + branded Next.js dashboard) in one shot:

```bash
./scripts/dev/launch.sh
# core      → http://127.0.0.1:3001
# analytics → http://127.0.0.1:8002
# dashboard → http://127.0.0.1:3000   (Mandate Console)
```

To deploy: either the **docker-compose** files in [`deploy/`](deploy/), or the **no-Docker native/systemd** path in [`deploy/native/`](deploy/native/) (Caddy auto-TLS + `sauronid-core` / `sauronid-dashboard` units). The [`scripts/demo/democtl.sh`](scripts/demo/) driver wraps the native path (`build-native` → `deploy-native` → `runner` → `status`) and brings up the real LLM agent behind the Console. Full guide: [docs/operations.md](docs/operations.md).

## Mandate Console — the web dashboard

A branded Next.js console at `dashboard/` reads **only live data from the running core** — no parquet, no fixtures, no mocks. Main routes (nav label → code path):

| Route | What it shows |
|---|---|
| **Home** (`/`) | Live counters — total agents, calls today, protected (blocked) today — computed from real agent egress, not estimates |
| **Console** (`/try`) | The interactive console: pick a model (**local gemma** on a GPU box, or **cloud Groq**), give a real agent a task, watch it use tools and answer — then make it misbehave (replay / tamper / revoke) and watch the core reject it live (HTTP 409/401), and seal every action into Bitcoin. Every step is a real signed call to the core. |
| **Protected** (`/protected`) | Governance stops that actually happened — agent calls the core rejected (replayed nonce, tampered body, revoked agent), each with the real 4xx status. Sourced from blocked egress, never inferred. |
| **Activity** (`/activity`) | Live feed of every real agent call (allowed + stopped), filterable by agent / result / date |
| **Proofs** (`/proofs`) | Bitcoin (OpenTimestamps) + Solana anchor batches. Each batch's Merkle root is **one-click verifiable** — download its `.ots` proof and check it with the open-source `ots` tool (`ots upgrade` / `ots info`). Honest three-state surface per ADR-001 (Solana ≤30 s, BTC pending ≤1 h, dually anchored). |
| **Policies** (`/policies`) | Policy invariants bound to agents, with an evaluation endpoint |
| **Cohorts** (`/cohorts`) | Differential-privacy published cohort stats (k-anonymity gated) |
| **Compliance** (`/compliance`) | Compliance screening surface (provider operator-supplied) |
| **Settings** (`/settings`) | Tenant + core-connection settings |

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

# `user_session` + `user_key_image` come from your end-user auth flow — the
# human owner delegating to this agent. Requires the `agent-action-tool` binary
# on PATH (or set $SAURONID_AGENT_ACTION_TOOL) for default keypair generation.
client = SauronIDClient(base_url="https://sauronid.your-company.internal")
agent = register_llm_agent(
    client,
    user_session=user_session,
    user_key_image=user_key_image,
    model_id="claude-opus-4-8",
    system_prompt=open("prompts/research_agent.md").read(),
    tools=["search", "fetch"],
)

# agent.call(method, path, ...) signs every request with the agent's per-call
# key (DPoP-style) and binds the config digest — a tampered body, replayed
# nonce, or drifted config is rejected server-side.
result = agent.call("POST", "/internal/api/search", json_body={"query": "..."})

# For leashed + on-chain-anchored actions (payments, KYC consent): request a
# challenge, ring-sign it with the agent's ring secret, then submit the proof.
#   proof = agent.sign_action_challenge(challenge_json)
#   agent.call("POST", "/agent/payment/authorize", json_body={..., "agent_action": proof})
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
SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh
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

## Repo layout

```
core/                  Rust axum service (~14k lines core Rust)
dashboard/             Next.js Mandate Console (live data from core)
clients/python/        Python adapter (SignedAgent + LangChain/OpenAI/Anthropic wrappers)
agentic/               TypeScript adapter
redteam/               16-attack empirical suite + 18-attack Tavily fuzzer + competitive benchmark
contracts/             Solana Anchor program (sauron_ledger)
migrations/postgres/   Postgres schema
schemas/               Shared JSON schemas (external crypto, attestation)
zkp/                   ZKP issuer + circuits

scripts/dev/           Dev orchestration shell scripts (quickstart, launch, start, ...)
scripts/demo/          Live-demo driver (democtl.sh) + real LLM agent-runner (agent_runner.py)
scripts/               Python simulation + audit utilities (simulate_real_actions.py, solana_audit.py, ...)
deploy/                docker-compose (dev/prod/postgres) AND a no-Docker native/systemd path
                       (deploy/native/: vm-setup.sh, *.service, Caddyfiles) + Solana setup
branding/              BRANDING.md, logo.svg, brand-book.pdf
docs/                  threat-model, operations, production-readiness, roadmap, competitive-benchmark

archive/banking-2025/  Pre-pivot bank-KYC code. Feature-flagged off by default; kept for git
                       continuity. Do not depend on. Removed from active product surface.
```

## Critical files

- Core service: [`core/`](core/) — Rust, axum, ~14k lines core Rust (count: `find core/src -name '*.rs' | xargs wc -l`).
- Mandate Console: [`dashboard/`](dashboard/) — Next.js + Chart.js, dark branded UI reading live core data only.
- Brand system: [`branding/`](branding/) — `BRANDING.md`, eye logo, brand book.
- TypeScript client: [`agentic/`](agentic/) — `signCall`, `register`, `popKeys`.
- Python client: [`clients/python/sauronid_client/`](clients/python/sauronid_client/) — LangChain + OpenAI + Anthropic adapters.
- Empirical attack suite: [`redteam/`](redteam/) — 9 invariant scenarios + 16-attack empirical suite + 18-attack Tavily fuzzer.
- Simulation + audit scripts: [`scripts/`](scripts/) — Python utilities; dev orchestration shells under [`scripts/dev/`](scripts/dev/).
- Deploy config: [`deploy/`](deploy/) — docker-compose (dev/prod/postgres) **or** no-Docker native/systemd ([`deploy/native/`](deploy/native/): `vm-setup.sh`, `sauronid-core.service`, `sauronid-dashboard.service`, Caddyfiles).
- Live-demo driver: [`scripts/demo/democtl.sh`](scripts/demo/) — build-native / deploy-native / runner / status; pairs with the real LLM agent-runner (`agent_runner.py`) behind the Console.
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
make clean && ./scripts/dev/quickstart.sh
```

The full session log of how this was built (multi-week, agent-driven) is intentionally not in the repo. The codebase is the spec.
