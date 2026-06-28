# SauronID Threat Model

This document states what SauronID protects against, what it does NOT protect against, and the assumptions every operator must hold for the security claims to be meaningful. Read it before deploying.

## In scope: what SauronID protects against

| Threat | Mechanism |
|---|---|
| **Captured A-JWT replay** | Single-use JTI table (`ajwt_used_jtis`); atomic UNIQUE-constraint insert; periodic GC. |
| **A-JWT replay against a different endpoint or with a mutated body** | Per-call signature middleware (`require_call_signature`). Agent signs `method\|path\|sha256(body)\|ts\|nonce` with its registered Ed25519 PoP key. Single-use nonce in `agent_call_nonces`. |
| **Agent intent drift** | `intent_json` embedded in A-JWT; intent is a server-evaluated leash, not metadata. Delegated agents must register a child intent that is a strict subset of the parent's scope. |
| **Agent code tampering** | `agent_checksum` (SHA-256 of agent config) is bound at registration and verified on every call; mismatch invalidates the token. |
| **Concurrent double-spend on single-use tokens** | Atomic `UPDATE ... WHERE field = old_value` with `rows_changed` check on consent tokens, payment authorizations, credential claims, lightning invoices, bank attestation nonces. No SELECT-then-UPDATE windows. |
| **Session token forgery** | Constant-time HMAC comparison via `subtle::ConstantTimeEq`. No timing oracle. |
| **Admin key brute-force** | Production: ≥32-byte random keys required. Dev: warns on known-weak defaults. Read-only vs full-write key roles. |
| **Cross-origin attacks** | Hard panic if `SAURON_ALLOWED_ORIGINS` resolves to no valid headers; never falls back to permissive CORS. |
| **Endpoint enumeration / register flooding** | Sliding-window rate limits via `risk::check_and_increment` on `/agent/register`, `/agent/verify`, `/kyc/retrieve`, `/agent/payment/authorize`, `/agent/kyc/consent`. |
| **Tamper-evident audit log** | Merkle commitments anchored to Bitcoin via OpenTimestamps (`opentimestamps` provider in `bitcoin_anchor.rs`); upgraded asynchronously to full Bitcoin block attestations. External parties verify via `ots verify` CLI. |

## Agent boundary enforcement: where the leash applies

Every agent-initiated route now carries the per-call DPoP-style signature in enforce mode. Operators set `SAURON_REQUIRE_CALL_SIG=1` to fail-close. Default (development) is advisory.

| Endpoint | A-JWT | PoP-on-challenge | Per-call DPoP sig + config digest | Action-envelope ring sig |
|---|:-:|:-:|:-:|:-:|
| `/agent/payment/authorize` | ✓ | ✓ if registered | ✓ **enforced** | — |
| `/agent/payment/nonexistence/material` | ✓ | — | ✓ **enforced** | — |
| `/agent/payment/nonexistence/verify` | ✓ | — | ✓ **enforced** | — |
| `/agent/action/challenge` | ✓ | — | ✓ **enforced** | ✓ |
| `/agent/kyc/consent` | ✓ | ✓ | ✓ **enforced** | ✓ |
| `/agent/vc/issue` | ✓ | ✓ | ✓ **enforced** | — |
| `/policy/authorize` | ✓ | — | ✓ **enforced** | — |
| `/agent/egress/log` | ✓ | — | ✓ **enforced** | — |
| `/agent/verify` | ✓ | ✓ | — *(verifier endpoint, third-party callable)* | — |
| `/agent/action/receipt/verify` | — | — | — *(public verifier; can be called by anyone with the receipt)* | ✓ in receipt |
| `/agent/register` | — | — | — *(no agent exists yet)* | — |

**Two leashes exist** because they target different threat classes:

- **Per-call DPoP sig** binds the call to method, path, exact body bytes, timestamp, and nonce. Defeats: replay, body tampering, cross-endpoint replay. Currently applied only to `/agent/payment/authorize`.
- **Action-envelope ring sig** binds the call to a canonical envelope `{action, resource, merchant, amount, nonce}`. Defeats: replay (via `agent_action_nonces`), action substitution. Currently applied to all `/agent/action/*` and `/agent/kyc/consent`.

**Gap 1: closed.** Per-call signature is now applied to every agent-initiated route. Empirical test A4 (cross-endpoint A-JWT replay) verifies the failure mode against `/agent/payment/authorize`; the same protection now extends to `/agent/vc/issue`, `/policy/authorize`, `/agent/kyc/consent`, `/agent/payment/nonexistence/*`, `/agent/action/challenge`, and `/agent/egress/log`.

## Gap 4 enforcement: agent runtime config drift

Every protected request must include `x-sauron-agent-config-digest` matching the server-stored `agents.agent_checksum`. The middleware uses constant-time compare (`subtle::ConstantTimeEq`) and rejects with 401 on mismatch.

**How the digest is bound to the agent's actual behaviour:**

1. At `/agent/register`, the operator submits `agent_type` (e.g. `llm`) + `checksum_inputs` (a structured object with required fields per type — for `llm`: `model_id`, `system_prompt`, `tools`).
2. SauronID canonicalises the JSON, computes `SHA-256`, stores both the raw inputs and the resulting `sha256:<hex>` digest.
3. The agent runtime computes the same digest from its actual loaded config and sends it on every protected call.
4. If an attacker (or careless operator) flips the system prompt without first calling `POST /agent/{id}/checksum/update`, the runtime's computed digest no longer matches the server's stored value. Every call to a protected endpoint rejects with 401 `agent runtime config digest does not match registered checksum (config drift…)`.

**Empirical proof:** test A16 in `redteam/dist/scenarios/empirical-suite.js` registers an LLM agent, then sends a payment-authorize call with a mismatched digest header. Server returns 401 with `drift` in the body. Verified 16/16 in enforce mode.

**Honesty assumption:** the runtime computes its digest from its actual config. A compromised host can lie — that's gap 3, mitigated by hardware-backed key + attestation (below).

## Gap 3 mitigation: hardware-backed PoP keys (vendor-neutral)

To make the runtime "honest" about its digest, the PoP signing key must live in hardware that:

1. Generates the keypair with the public key exportable but the private key non-exportable.
2. Only signs after the host has booted into a measured state.
3. Returns an attestation document signed by a manufacturer-rooted key chain proving (1) and (2).

**SauronID is NOT bound to any single vendor.** The verification primitive in `core/src/attestation.rs` accepts seven kinds:

| Kind | Hardware | Cloud-agnostic | Attestation format | Status this commit |
|---|---|:-:|---|---|
| `tpm2_quote` | TPM 2.0 chip (every motherboard since ~2016) | yes | `TPMS_ATTEST` + signed by AIK, AIK cert chained to TPM-vendor root | recognised, verifier roadmapped |
| `sgx_quote` | Intel Xeon | yes | DCAP quote + Intel root | recognised, verifier roadmapped |
| `sev_snp` | AMD EPYC | yes | SEV-SNP report + AMD root | recognised, verifier roadmapped |
| `arm_cca` | ARM CPUs | yes | CCA token + ARM root | recognised, verifier roadmapped |
| `nitro_enclave` | AWS Nitro | AWS-only | COSE_Sign1 + AWS root | recognised, verifier roadmapped |
| `apple_secure` | Apple Silicon | macOS/iOS only | DeviceCheck assertion | recognised, verifier roadmapped |
| `ed25519_self` | any (operator-controlled root key) | yes | Ed25519 signature over runtime measurement | **fully verified** in this commit |

`ed25519_self` is the operator-rooted path: the operator signs measurements with their own key (HSM, YubiKey, air-gapped laptop). Cryptographically prevents tampering once signed. The operator must honestly compute the measurement — this is a weaker root of trust than a TPM/SGX manufacturer root, but stronger than no attestation at all.

The vendor-rooted kinds (`tpm2_quote` etc.) are recognised but return `AttestationError::NotImplemented` until the per-vendor cert chain validators land. Each is a contained crypto-only addition — no AWS or other cloud SDK dependency. Roadmap:

- `Tpm2Quote`: parse `TPMS_ATTEST` with `nom`, verify EK→AIK chain via `webpki`, signature via `ring`. Vendor roots ship as static bytes (Infineon, STMicro, Microsoft, Intel, AMD, IBM).
- `SgxQuote`: parse DCAP quote, verify against Intel SGX root cert.
- `SevSnpReport`: parse SEV-SNP report, verify against AMD root.
- `NitroEnclave`: COSE_Sign1 verification against AWS Nitro root cert. Equivalent to `aws-nitro-enclaves-cose` but standalone — no AWS API calls.

**There is no AWS lock-in.** Operators on bare metal, on Azure, on GCP, or on any cloud can use `Tpm2Quote` (every modern x86 / ARM motherboard has one) once that verifier path lands. Operators wanting maximum control today use `Ed25519Self` with their own operator-controlled root key.

When hardware-backed: even host compromise no longer leaks the PoP private key. The attacker can call SauronID using whatever public key the hardware exposes, but signing every call requires reaching the hardware — which a compromised userland process cannot do without also compromising the firmware boundary.

### Enforced at registration (not just available)

Previously the attestation verifiers were reachable only via the standalone `POST /v1/attestation/*` route; `/agent/register` stored the blob verbatim without verifying it. Registration now runs `enforce_registration_attestation` (`core/src/attestation/mod.rs`) inline:

- The operator asserts the runtime measurement via `expected_measurement_hex`. `verify_attestation` checks BOTH the signature / cert-chain AND that the blob attests to exactly that measurement — an attacker who asserts a blessed value but whose blob attests a different state is rejected with `MeasurementMismatch`.
- `SAURON_REQUIRE_HARDWARE_ATTESTATION=1` rejects `none` / `server_derived` kinds outright (a verifiable hardware kind becomes mandatory).
- The expected measurement is sourced one of two ways:
  - **Mode (a) — pre-registered (`SAURON_REQUIRE_PREREGISTERED_MEASUREMENT=1`):** the asserted measurement must be in the operator's out-of-band golden allowlist (`SAURON_ATTESTATION_GOLDEN_MEASUREMENTS`). Defends a compromised-at-first-boot host, whose blob attests a non-golden measurement and therefore cannot pass.
  - **Mode (b) — trust-on-first-use (default):** no allowlist; the genuine measurement the operator asserts is accepted and pinned to `agents.attestation_pcr_set`. Catches post-enrollment drift, not a compromised first boot.

Coverage today: `ed25519_self` (full), `tpm2_quote` (M2 verifier), `nitro_enclave` (COSE path). `sgx` / `sev_snp` / `arm_cca` / `apple_secure` still return `NotImplemented` and so cannot pass the gate.

## Gap 2 mitigation: agent egress logging

`POST /agent/egress/log` records every outbound third-party API call the agent makes. The endpoint is itself per-call-sig-protected, so log entries are bound to the specific agent + signed by its PoP key + carry the matching config digest. Each row is included in the next agent-action anchor batch and committed to Bitcoin (OTS) and Solana (Memo) — making after-the-fact tampering require forging both chains.

**Voluntary reporting today.** Operators must wire their agent runtime to call this endpoint before making any outbound request. Enforcement requires either:

- **Network policy**: kubectl NetworkPolicy / iptables / firewall rule blocking outbound traffic except via the SauronID egress proxy.
- **Forward proxy** (Phase 5): SauronID listens on an internal port as an HTTP CONNECT proxy. Agent's HTTP client routes through it. SauronID validates each call against `intent_json.egress_allowlist` and signs+forwards only allowed targets.

The forward-proxy implementation is documented but not shipped this session. Operators wanting strict enforcement should either layer Cloudflare AI Gateway / Anthropic MCP in front of the agent (battle-tested) or wait for the next-session deliverable.

## Audit-log integrity for agent actions

Every `/agent/action/receipt/verify` call appends a row to `agent_action_receipts`. Without on-chain anchoring, a database-write attacker could rewrite that history.

**SauronID anchors the agent-action receipt root every `SAURON_ACTION_ANCHOR_INTERVAL_SECS` (default 600 s)** to BOTH:

- **Bitcoin** via OpenTimestamps calendars → real Bitcoin block attestation after ~1 hour.
- **Solana** via Memo Program → finalized in ~30 s.

External auditors verify by:

1. Pull the row from `agent_action_receipts`.
2. `GET /admin/anchor/agent-actions/proof?receipt_id=<rcp_…>` → returns merkle path + `batch_root_hex` + `btc_anchor_id` + `sol_anchor_id`.
3. Re-derive `leaf = SHA256(receipt_id || '|' || action_hash || '|' || created_at_ascii)`. Walk the merkle path. Compare to `batch_root_hex`.
4. Look up `bitcoin_merkle_anchors WHERE anchor_id = btc_anchor_id`, run `ots verify <ots_receipt_blob>` against the root.
5. Look up `solana_merkle_anchors WHERE anchor_id = sol_anchor_id`, run `solana getTransaction <signature>`. Memo body should be `sauronid:v1:<batch_root_hex>`.

Tampering with any single receipt requires forging both Bitcoin and Solana attestations of the matching root. Not realistic.

## Agent-type agnosticism — what the operator must define

SauronID's binding layer (`agent_id`, `pop_public_key_b64u`, `ring_key_image_hex`, `intent_json`, A-JWT, per-call sig) is fully type-agnostic. Same primitives work for an LLM agent, a rule-based bot, an MCP server, or a browser-automation script.

**The catch is `agent_checksum`.** SauronID stores it but does NOT define what it covers. The operator chooses what fields go into the SHA-256. If the operator picks a too-narrow definition, an attacker can mutate the agent's behaviour without changing the checksum, and the leash is silently bypassed.

Recommended checksum scope per agent type:

| Agent type | `agent_checksum = SHA256(...)` should cover |
|---|---|
| **LLM agent** (Claude, GPT, Gemini, etc.) | `model_id`, full `system_prompt`, ordered `tool_list`, `temperature`, `top_p`, `max_tokens`, any `response_format` schema, the SDK version |
| **Anthropic MCP server** | full `manifest_json`, ordered `tool_signatures`, sub-agent identifiers, hash of any embedded prompts |
| **Rule-based bot / cron job** | container image SHA (e.g. `sha256:...` from registry), config file SHA |
| **Browser automation (Puppeteer/Playwright)** | script file SHA, `package-lock.json` hash, env var manifest |
| **Function-calling app (OpenAI Assistants, etc.)** | assistant ID, `instructions`, ordered `tools`, `model` |
| **Foundation-model-agnostic agent framework** (LangChain, LlamaIndex) | code SHA + lockfile SHA + chain definition serialized |

If the checksum changes between calls, SauronID's downstream policy decision can detect the mutation. If the operator omits a field that an attacker can mutate, the mutation is invisible.

The 9-scenario invariant suite includes `delegation_scope_denied` and `parent_empty_scope_denied` which exercise the `intent_json` leash. Checksum-scope correctness is **on the operator**, not on SauronID.

## STRIDE per component

The STRIDE matrix below decomposes the system into five components and walks each through Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege. Per-row: documented threat, in-code mitigation with file:line citation, residual risk that pentest should hammer.

### Core service (Rust axum HTTP service, `core/src/main.rs`)

| Category | Threat | Mitigation (file:line) | Residual risk |
|---|---|---|---|
| **Spoofing** | Caller forges admin auth | Bearer-key constant-time compare; min-32-byte production keys; multi-key list (`core/src/admin.rs::build_admin_auth_config` ~L52, ~L99-107) | Operator must protect the key; covered in `docs/key-rotation.md` §1 |
| **Spoofing** | Caller forges agent identity | A-JWT signed under `SAURON_JWT_SECRET`; PoP-on-challenge; per-call DPoP sig over method/path/body-hash/ts/nonce (`core/src/agent.rs:1429`, `core/src/agent.rs:1587`) | Agent host compromise → PoP key leak; mitigate with hardware attestation |
| **Tampering** | Body mutation after sig | Sig covers `sha256(body)` exact bytes; mismatch → 401 (`core/src/agent.rs:1429`) | Empirical test A5 covers; pentest should also try whitespace-only body mutations |
| **Tampering** | Agent config drift | `x-sauron-agent-config-digest` cross-checked vs registered `agent_checksum` (constant-time compare via `subtle::ConstantTimeEq`) | Checksum scope is operator-defined; narrow scope → silent bypass (see "Agent-type agnosticism" §) |
| **Repudiation** | Operator denies an action happened | Every action receipt anchored to Bitcoin OTS + Solana memo; external `ots verify` reproduces | Anchoring latency: receipt provable after ≈ 30 s (Solana) / ≈ 1 h (Bitcoin) |
| **Repudiation** | Tenant denies an admin action | Sprint 12 security audit log captures `(actor, action, target, ts)` rows, anchored in next batch | Audit log retention is operator-configured; default 90 d |
| **Information disclosure** | Cross-tenant data leak | Tenancy middleware scopes every query by `tenant_id` (`core/src/tenancy/mod.rs`, applied per-route in `core/src/main.rs`) | Pentest: try UUID enumeration; redteam `tenant-list-leak.ts` covers |
| **Information disclosure** | Timing oracle on session HMAC | `subtle::ConstantTimeEq` everywhere on secret comparison | Confirm no string-compare snuck in during a refactor |
| **Denial of service** | Endpoint flooding | Sliding-window rate limits via `risk::check_and_increment` on `/agent/register`, `/agent/verify`, `/kyc/retrieve`, `/agent/payment/authorize`, `/agent/kyc/consent` (`core/src/risk.rs`) | Per-tenant rate limit; one noisy tenant cannot starve others (redteam `tenant-rate-limit-cross.ts`) |
| **Denial of service** | Cryptographic CPU exhaustion (slow proof verify) | ZK verify timeout; rate-limited on `/v1/proofs/verify` | Pentest: submit deeply-nested malformed Groth16 proofs and measure |
| **Elevation of privilege** | Read-only admin escalates to write | Distinct `read_only_keys` vs full-write key set; scope check at route layer (`core/src/admin.rs` ~L77-85) | Operator misconfiguration risk; covered by startup validator |
| **Elevation of privilege** | Agent escalates beyond intent_json | `assert_child_scopes_subset_of_parent` on every delegate-issue; intent JSON treated as server-evaluated leash, not metadata | Empirical test A10 + delegation-scope-denied redteam scenario |

### SDK (agentic, `agentic/src/enforcement.ts`)

| Category | Threat | Mitigation (file:line) | Residual risk |
|---|---|---|---|
| **Spoofing** | Agent forks process, never calls `bind()` | None at SDK layer — by design (see redteam `binding-direct-tool-call.ts`) | **Server-side** policy evaluation is the authoritative gate (`/v1/policy/evaluate`). SDK is a fast advisory checkpoint. |
| **Tampering** | Agent mutates the local `BudgetTracker` counter | None at SDK layer (`agentic/src/enforcement.ts::BudgetTracker`) | Server-side spend ledger (`core/src/repository.rs::insert_spend_log` ~L1714) is authoritative |
| **Tampering** | Agent lies in `classifyAction` | None at SDK layer | Server re-classifies on `/v1/policy/evaluate`; redteam `binding-classifier-lie.ts` documents the chain |
| **Repudiation** | Agent claims it never called the tool | SDK does not produce receipts; receipts come from server-side acceptance | Tampered local logs are useless; the audit chain (server side, anchored) is the source of truth |
| **Information disclosure** | SDK caches stale policy after server-side revoke | `PolicyCache::refresh` keeps last good copy on 404 (documented; redteam A4 / `binding-revoke-replay.ts`) | Window = `refreshIntervalMs`. Operator picks the trade-off. |
| **Denial of service** | Agent stalls server with very large bind chains | Per-call signature requires a fresh nonce on every call; server rate limits per-agent | n/a — SDK runs in the agent's own process |
| **Elevation of privilege** | Agent imports the underlying tool directly | Documented limitation; see redteam `binding-direct-tool-call.ts` | Defence-in-depth: server-side cross-check denies regardless |

### Dashboard (React + TS, `dashboard/`)

| Category | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **Spoofing** | XSS / impersonation of an operator | CSP headers from the edge proxy (operator's responsibility); session cookie HttpOnly + Secure | Dashboard is operator-internal; not exposed publicly in default deploy |
| **Tampering** | Agent-supplied JSON renders as HTML | React's default JSX escaping; explicit `dangerouslySetInnerHTML` never used for agent-supplied content | Confirm via grep on each release |
| **Repudiation** | Operator denies a dashboard-initiated action | Every mutating call goes through `/admin/*`; audit log row written | Same as core |
| **Information disclosure** | Dashboard shows another tenant's data | Per-session tenant scope from server; UI just renders what server returns | Server-side tenancy is the choke point, not the UI |
| **Denial of service** | Long-poll exhaustion | Dashboard uses bounded SSE; no unbounded polls | n/a |
| **Elevation of privilege** | Read-only user runs a write action | Server-side scope check on the admin key/JWT; UI hides buttons but does not enforce | Always server-enforced |

### ZK prover (`zkp/sdk`, circuits in `zkp/circuits/`)

| Category | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **Spoofing** | Prover submits a proof under a different `vk_id` | Verifier checks `vk_id` matches the metric catalog (`core/src/zk_verifier.rs:44`, `core/src/aggregation/verify.rs`) | Redteam `proof-wrong-vk.ts` covers |
| **Tampering** | Prover flips a public input | Public-input hash signed into the proof; Groth16 verify fails on mismatch | Redteam `proof-tampered-root.ts` |
| **Repudiation** | Prover claims they never produced a proof | All accepted proofs are stored with their submission timestamp and anchored in the next batch | n/a |
| **Information disclosure** | Proof leaks private inputs | Groth16 is statistically zero-knowledge under the trusted setup assumption | If trusted setup is compromised, ZK property fails — see `docs/cryptographic-assumptions.md` §8 |
| **Denial of service** | Heavy verifier load | Per-tenant verify rate limit; verify spawns external `snarkjs` with a timeout | Pentest: measure verify-CPU per malformed-proof shape |
| **Elevation of privilege** | Forge a proof of an arbitrary statement | Knowledge soundness of Groth16 under honest setup | **Current dev ceremony makes this possible.** Production requires multi-party ceremony per `zkp/ceremony/README.md`. Loudly flagged in `docs/cryptographic-assumptions.md` §8. |

### Anchor providers (Bitcoin OTS, Solana RPC)

| Category | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **Spoofing** | Malicious calendar returns fake OTS receipts | `ots verify` against Bitcoin chain; calendar receipt alone is just a promise, the upgrade to a full Bitcoin attestation roots in PoW | Calendar downtime ≠ broken security; just delayed upgrade |
| **Spoofing** | Malicious Solana RPC returns fake `getTransaction` | External verifier checks via a different RPC; signature recoverable from on-chain data | Operator configures multiple RPCs (`docs/disaster-recovery.md` §2) |
| **Tampering** | Calendar drops our submission | Multiple calendars; submission retried; we tolerate calendar churn | Configure ≥ 2 calendars |
| **Repudiation** | Bitcoin / Solana retroactively reverses | PoW reorgs beyond a few blocks are infeasible at deployed hashrate; Solana finalisation is BFT under <33% Byzantine assumption | Trust the chain's security model |
| **Information disclosure** | Anchor leaks pre-image | Anchor is hash-only; pre-image stays operator-side | Confirm via tracing logs — anchor body should be `sauronid:v1:<root_hex>` and nothing else |
| **Denial of service** | All calendars / RPCs simultaneously down | Bitcoin-only fallback (set `SAURON_SOLANA_ANCHOR_ENABLED=0`); Solana-only fallback acceptable for short term | DR runbooks: `docs/disaster-recovery.md` §1-2 |
| **Elevation of privilege** | n/a (anchor providers do not authenticate to us) | n/a | n/a |

## Abuse cases

Non-exhaustive list of hostile scenarios pentest should specifically rehearse. Each ties to one or more redteam scripts in `redteam/src/scenarios/`.

| Abuse case | Description | Mitigation | Redteam scenario |
|---|---|---|---|
| **Policy bypass via tampered SDK** | Attacker patches the agentic SDK locally to skip the `bind()` wrapper or lie about classification / budget. | Server-side `POST /v1/policy/evaluate` re-evaluates with truthful data + authoritative spend ledger. SDK is advisory only. | `policy-bypass.ts`, `binding-*.ts` (5 scripts) |
| **Server admin key leak** | `SAURON_ADMIN_KEY` ends up in a public git history / cloud snapshot / .env in a Docker image. | Multi-key support enables zero-downtime rotation (`core/src/admin.rs::build_admin_auth_config`); production startup rejects keys < 32 B. Procedure: `docs/key-rotation.md` §1. | n/a (key-management process, not a runtime attack) |
| **Ceremony coordinator collusion** | The party running the ZK trusted setup keeps the toxic waste secretly. | Multi-party ceremony per `zkp/ceremony/README.md`. As long as ≥ 1 honest party deletes their share, soundness holds. Until that ceremony runs, dev vk is unsound — loudly flagged. | `proof-*.ts` (5 scripts, including `proof-wrong-vk.ts`) |
| **Anchor provider downtime** | Bitcoin calendars + Solana RPCs all return errors simultaneously. | Backlog tolerated; queued anchors drain on recovery. Bitcoin-only or Solana-only mode acceptable for short outages. Runbooks: `docs/disaster-recovery.md` §1-2. | n/a (infrastructure attack, not a runtime attack) |
| **Solana RPC censorship** | RPC silently drops our memo writes. | Multi-RPC failover (`SAURON_SOLANA_RPC_FALLBACK_URLS`); Bitcoin-only fallback. We detect by comparing in-flight queue depth against expected drain rate. | n/a |
| **Stale-policy replay window** | Server-side revoke happens; SDK cache still has the old policy until refresh interval. | Documented window. Future sprint: server-pushed revocation feed. | `binding-revoke-replay.ts` |
| **Cross-tenant existence probe** | Attacker enumerates UUIDs hoping to learn which `(tenant, policy_id)` pairs exist. | `404 Not Found` returned uniformly for misses, no `403 Forbidden` that would leak existence. | `tenant-list-leak.ts`, `tenant-spend-leak.ts` |
| **DP cohort de-anonymisation** | Attacker pulls cohort numbers across N snapshots hoping to average out the noise. | Per-period ε budget caps total privacy loss; k-anonymity suppresses small cohorts | `dp-cohort-deanonymize.ts` |
| **Egress voluntary-log gap** | Attacker compromises agent host; emits an `agent_egress_log` entry claiming an action that never happened, or omits one that did. | Log entries are signed under PoP + bound to `agent_id` + anchored; pentest scenario documents the trust model. **Voluntary by design today** — forward-proxy enforcement deferred. | `egress-leak-claim.ts` |
| **TEE revocation cascade** | Agent registered with `Tpm2Quote` / `NitroEnclave`; agent then revoked; attacker reuses the attestation blob for a new agent registration. | Revoke cascades on the agent record; attestation hash + agent_id uniqueness check prevents reuse. | `tee-revoke.ts` |

## Out of scope: what SauronID does NOT protect against

| Threat | Why out of scope | Operator mitigation |
|---|---|---|
| **Compromised agent host** | If an attacker reads the agent's PoP private key from process memory, they can sign arbitrary requests as that agent. | Run agents in confidential-compute environments (TEE/Nitro/SEV-SNP); rotate per-agent keys frequently; bind PoP keys to attested hardware where required. |
| **Compromised admin key** | Anyone holding `SAURON_ADMIN_KEY` can mint clients, revoke agents, read all data. | Operator must protect via Vault Transit / AWS KMS / split control. Never commit the key. |
| **Compromised secret backend (Vault/KMS)** | If Vault root token or KMS key policy is misconfigured, all wrapped secrets leak. | Standard secret-manager hygiene: separate access roles, audit Vault `/sys/audit`, rotate KMS keys on schedule. |
| **DB exfiltration** | An attacker with read access to the SQLite/Postgres file sees all key images, agent registrations, consent logs. PII screening data, if enabled, also exposes nationality/dob. | TLS at the DB tier; encryption at rest; restrict OS-level file access; encrypt the data tier (Postgres TDE or LUKS). |
| **Network MITM on the bus** | If the SauronID core <-> ZKP issuer / Vault / KMS / Postgres traffic is unencrypted, secrets leak in transit. | Enforce TLS on all internal hops; mTLS between core and issuer is recommended. |
| **Untrusted ZKP issuer** | If the ZKP issuer is compromised, all VCs it signs can be forged. | Wrap the issuer seed in Vault Transit / KMS (same envelope-encryption pattern as the core). Optional Phase: deploy issuer in a Nitro Enclave. |
| **Quantum adversary** | Ed25519, ristretto255, secp256k1 signatures are not post-quantum. | Out of scope; revisit when NIST PQC standards stabilize for signing schemes. |
| **End-user identity verification (KYC/AML)** | SauronID is **agent identity**, not human identity. The bank-KYC, sanctions-screening and PEP modules are optional, opt-in features for legacy deployments and are NOT part of the core agent-binding product surface. | If you need OFAC/PEP screening, set `SAURON_DISABLE_BANK_KYC=0` and wire your own provider into `compliance_screening.rs`. SauronID does not replace your existing IdP. |
| **Application-layer authorization** | SauronID verifies the agent is who it claims to be and has scope X. It does NOT decide whether the agent's specific request is allowed by your business rules. | Implement application-level RBAC/ABAC on top of `VerifiedCallSig` + `intent_json` extracted from request extensions. |
| **Physical security of operator host** | If an attacker has physical access to the SauronID host, they can dump RAM, copy disk, install firmware implants. Game over for that host. | Standard datacenter / cloud-region physical security; HSM-backed key storage so even disk dump does not yield raw secrets; consider TEE-resident execution for the most sensitive paths. |
| **Social engineering of operators** | Phishing / pretexting the human operator into sharing the admin key, approving a malicious config push, signing a malicious DKG share rotation. | Out of scope for code. Operator-level controls: dual-control admin actions (`SAURON_ADMIN_DUAL_CONTROL=1`), hardware MFA on all admin login paths, phishing-resistant FIDO2 keys for the operator's IdP, security awareness training. |
| **Supply-chain compromise of upstream crates** | A malicious version of a Rust crate (or an npm package in the SDK) ships through cargo / npm, executing during build. | `Cargo.lock` / `package-lock.json` committed; CI verifies; consider `cargo-vet` / `cargo-deny` / `npm audit`. SBOM tooling is a separate sub-task. |
| **Operator builds and ships a malicious binary** | If the operator themselves is hostile or compromised at the build step, downstream tenants cannot defend against a backdoored binary. | Reproducible builds; binary attestation; out-of-band signed release notes. Independent verifiers should be able to rebuild from source and diff the binary. |

## Assumptions

For the security claims to hold, the operator must guarantee:

1. **The system clock is roughly correct.** Per-call signature skew is `±SAURON_CALL_SIG_SKEW_MS` (default 60 s). NTP-synced clocks on both client and server.
2. **Random number generation is healthy.** All Ed25519 keypair generation, JTI generation, nonce generation use system CSPRNG. Deploy on hosts with sane entropy sources.
3. **The Vault Transit token / KMS IAM role is not exfiltratable from the SauronID host.** Wrapped secrets only protect against database/disk leaks, not host compromise.
4. **The DB layer is consistent.** SQLite WAL provides atomic INSERT and UPDATE; Postgres provides the same. Eventual-consistency stores would break the TOCTOU fixes — do not back SauronID with an eventually-consistent KV store without restructuring the concurrency-control patterns.
5. **TLS terminates at a trusted edge.** SauronID itself does not require TLS, but every realistic deployment terminates TLS at an edge proxy (cloud load balancer, NGINX, Caddy).

## Verifying the claims

| Claim | How to verify |
|---|---|
| Replay protection | Run `redteam` `jti_replay_blocked` scenario. |
| Per-call signature | Run with `SAURON_REQUIRE_CALL_SIG=1` and execute `call_sig_binding` scenario (4 cases: missing/signed/replay/tamper). |
| TOCTOU fixes | (Phase 1.3 cargo integration tests TBD.) For now, manual concurrent `curl` against `/kyc/retrieve` with same `consent_token`. |
| OTS anchor | After a merkle commitment, query the `bitcoin_merkle_anchors` row, extract `ots_receipt_blob`, run `ots verify <blob>` against the original digest. |
| Rate limits | `risk` table grows with each call; metrics endpoint shows hit rates. |
| Observability | `/metrics` returns Prometheus exposition; `tracing` emits structured logs. |
