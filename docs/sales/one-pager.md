# SauronID — one-pager

**A fail-closed authorization and verifiable-audit boundary for AI agents.**
Apache-2.0, self-hostable, one Rust binary. Clients in Python, TypeScript, Go, plus an MCP server.

## The problem

Your LLM agents call real APIs with real credentials. Prompt injection, hostile tool output, or plain model error turns those valid credentials into damage — the agent is authenticated, so the API says yes. Identity stacks answer "who is calling". They do not bind what this exact call is allowed to do, with which exact body, how many times, under which still-current agent configuration.

## What SauronID does

- **Signed calls.** Every agent request is Ed25519-signed over tenant, method, path, canonical query, body digest, timestamp, one-use nonce, and the agent's registered config digest. A replayed nonce, tampered body, cross-endpoint reuse, or drifted system prompt/tool list is rejected server-side with a machine-readable error.
- **Server-side policy.** Intent leashes, delegation scope-subset checks, per-agent and per-human rate limits, byte and amount caps, and an egress capability gateway with exact host/method/path constraints, one-use capabilities, and SSRF/redirect refusal — evaluated by an independent gateway, never trusted to the agent process.
- **Verifiable receipts.** Actions land in a hash-chained audit log; Merkle commitments are anchored to Bitcoin (OpenTimestamps) and Solana, and transparent RISC Zero STARK statements verify locally against published image IDs. Your auditor checks the trail without trusting us — `ots verify` is enough.

## Why not just X

Each alternative is good at what it was built for. None was built for this.

| Alternative | What it does well | What it does not give you |
|---|---|---|
| **OAuth + DPoP only (RFC 9449)** | IETF standard, key-bound tokens, `htu`/`htm` endpoint binding, dozens of vetted libraries, every major IdP supports it | DPoP does not sign the request body; JTI replay tracking is left to the operator; no intent/policy layer, no config-drift detection, no anchored audit. SauronID's per-call signature is DPoP-style by construction and an opt-in RFC 9449 compatibility envelope exists (`SAURON_ACCEPT_DPOP=1`). |
| **Agent IdPs (Auth0 Agent Identities; Descope, Aembit are the same category)** | Managed credential issuance, rotation, revocation, SSO integration, SOC 2/ISO certifications, mature SDKs — they pass procurement today | The token proves identity, not the call: the same access token works across endpoints, bodies are not signed, no per-call nonce, no config-digest drift check, and audit logs are vendor-internal — you trust the vendor. (Attack-by-attack evidence in our comparison covers Auth0 Agent Identities specifically.) |
| **MCP permissions** | Standard tool-permission surface inside the agent framework; sensible session-token handling | Enforcement runs in the same process as the possibly-injected agent. No independent boundary, no body binding, no per-call replay protection, no tamper-evident audit. SauronID ships an MCP server so MCP agents get the external leash without SDK work. |
| **API gateways (Cloudflare Access-class)** | Global edge latency, terabit DDoS absorption, TLS, coarse rate limits — keep yours, SauronID sits behind it | No per-agent cryptographic identity, no body-bound signatures, no one-use capabilities, no verifiable receipts. |

Where peers win outright: standardisation, ecosystem size, compliance certifications, global edge. The full honest scorecard, including the rows we lose, is in [docs/empirical-comparison.md](../empirical-comparison.md).

## Proof points

- **16-attack suite, 16/16 blocked in fail-closed mode** — forged signatures, JTI and nonce replay, body tampering, cross-endpoint replay, timestamp skew, wrong-key, revoked-agent, delegation scope creep, TOCTOU double-spend, timing oracles, audit tampering, config drift. 10 attacks verified by live dynamic execution, 6 by source-code review against canonical patterns (dynamic harness for those is on the red-team roadmap).
- **You run it yourself, one command:**

  ```bash
  SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh
  ```

- **Latency, full signature stack:** p50 2 ms / p99 8 ms at concurrency 1; p50 13 ms / p99 25 ms at concurrency 10 (single node, local SQLite). Comparable to a single-node Ory Hydra; slower than a global edge network, because it is not one.
- Nearest comparable stack (DPoP + OAuth) scores ~10/16 on the same suite; methodology and per-attack verifiers in [docs/empirical-comparison.md](../empirical-comparison.md).

## Deployment

`docker compose up` for evaluation; production-shaped compose with fail-closed pins; Helm chart and Terraform module for Kubernetes; a no-Docker native/systemd path with Caddy auto-TLS. Index: [deploy/README.md](../../deploy/README.md). Audit trail ships to your SIEM as configuration, not a project: [docs/siem-integration.md](../siem-integration.md).

## Honest limits

SauronID is containment, not a proof that an agent is benevolent: a valid but overly broad policy still authorizes harm, and traffic that can bypass the gateway is outside its control — production requires a deny-by-default network boundary so the agent's only route is through the gateway. Today the supported topology is single-node SQLite (startup makes you accept this explicitly); the Postgres port is partial and HA is roadmap, not product. There are no compliance certifications yet; an external cryptography review is in progress and a public audit report plus bug bounty follow it. The is/is-not/cannot tables in the [README](../../README.md) and the [threat model](../threat-model.md) are the contract — we would rather you read them before the pilot than after.

## Read next

[README](../../README.md) · [Empirical comparison](../empirical-comparison.md) · [Threat model](../threat-model.md) · [Production readiness](../production-readiness.md) · [Security questionnaire (pre-answered)](security-questionnaire.md) · [Pilot brief](pilot-brief.md)
