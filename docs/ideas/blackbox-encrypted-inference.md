# Idea parking lot: blackbox.ai-style "encrypted inference layer"

Status: **not implemented, parked for later.** Captured 2026-06 from a review of https://www.blackbox.ai/.

## What blackbox.ai is (two products bolted together)

1. **Multi-agent coding orchestrator** — dispatch one task to N coding agents (Claude
   Code, Codex, Gemini, …) in parallel, a "Chairman LLM" scores each
   (correctness/performance/risk/complexity), picks a winner, opens a PR.
2. **"Encrypted inference layer"** — an LLM gateway: OpenAI-compatible API, CLI/IDE,
   "requests encrypted device→model→back," customer-managed keys, **zero data
   retention**, claimed throughput gains.

Core product is **closed-source / commercial** (~30M users). No forkable repo — the
public GitHub hits (GizAI/blackbox, sanzydev, hardvar) are unrelated community projects.

## What is worth copying — and what is not

- **Skip** the multi-agent + Chairman judge: out of SauronID's lane (binding/auth/audit),
  and the pattern is free (judge-panel orchestration). Not a product fit.
- **Worth it**: the **inference/egress gateway** with binding + **token+money ledger** +
  anchored audit + zero-retention. This is the SauronID forward-proxy (threat-model Gap 2)
  + the token-ledger we want anyway.

## Honest critique (do not repeat their marketing)

- "Encrypted from device to model and back" = **TLS + zero-retention policy + customer
  keys**. The provider still sees plaintext. It is NOT homomorphic/confidential inference.
- Real "provider can't see the prompt" needs **TEE-hosted inference** (Nitro/SEV enclave)
  — which reuses SauronID's attestation work (gap #4). FHE inference is impractical at LLM
  scale today.

## How to build it without paying blackbox

| blackbox feature | OSS path (self-host) | SauronID role |
|---|---|---|
| OpenAI-compatible multi-provider gateway, per-key budgets, retention toggle | **LiteLLM** (or Portkey gateway / Helicone) | front it: bind + anchor + token/money ledger |
| Multi-agent dispatch + scoring | judge-panel orchestration; agents via OpenHands/aider | out of scope |
| "Encrypted inference" (strong) | TEE-hosted model in Nitro/SEV enclave | reuse attestation gap #4 |
| Zero retention | gateway config | policy + anchored audit |

## Tie-ins to current roadmap

- The gateway is the **authoritative** place to count tokens (it is in-path), removing the
  host-reported honesty caveat on the token ledger.
- TEE-hosted inference is the natural next step after the registration attestation gate.

Decision when revisited: assemble (LiteLLM + SauronID front + optional TEE), do not
reimplement blackbox.
