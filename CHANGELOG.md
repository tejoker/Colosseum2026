# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-05

### Security

- Release security evidence fails on any skipped or non-dynamic adversarial scenario.
- Anonymous-ring administration derives tenant identity only from authenticated request context.
- Production publication is gated on an independent cryptographic review and deployed-system penetration test covering the exact release commit.
- Unexpected request panics are contained at the HTTP boundary; production fail-closed controls remain mandatory.

### Packaging

- Python and npm SDK artifacts are built and install-tested in the release gate.
- Transparent RISC Zero guest image IDs and native receipts are reproduced and independently verified for release tags without a per-project trusted setup.
- Load-test raw JSON artifacts and dependency locks are retained with the release evidence.

### Added (accessibility and adoption pass)

- 15-line quickstart flow in all three SDKs: `register_llm_agent` / `registerLlmAgent` / `RegisterLLMAgent` returning a `SignedAgent` with `.call()` in TypeScript and Go (previously Python-only)
- Framework adapters: LlamaIndex, CrewAI, AutoGen for Python (joining LangChain/OpenAI/Anthropic) plus generic `sauronid_client.wrap()`; Vercel AI SDK, OpenAI, and Anthropic adapters for TypeScript
- MCP server (`mcp-server/`, `@sauronid/mcp-server`) exposing the leash as seven tools to any MCP client
- Opt-in RFC 9449 DPoP compatibility envelope (`SAURON_ACCEPT_DPOP=1`, fail-closed in production without explicit acknowledgment)
- Teaching error envelope: 4xx responses from the central error type and call-signature middleware return `{"error": {"code", "message", "fix"}}` with stable machine-readable codes
- `GET /healthz` and `GET /readyz` endpoints; core Dockerfile hardened (non-root user, healthcheck)
- One-command evaluation: root `docker-compose.yml` boots core + dashboard + seeded demo tenant with zero configuration
- Helm chart (`deploy/helm/sauronid/`) and Terraform module (`deploy/terraform/`)
- OpenAPI 3.1 specification covering the full HTTP surface (`schemas/openapi.yaml`, 90 paths)
- Docs site source (`docs/site/`): concepts, per-language quickstarts, payments/egress/policies/SIEM guides, API reference
- Runnable examples (`examples/`), one folder per framework and use case
- Dashboard: getting-started wizard (`/welcome`), copy-as-curl API explorer (`/explorer`), French locale + switcher, keyboard-navigable tenant switcher, skip-to-content link, tokenized login page
- SIEM integration guide (`docs/siem-integration.md`)
- Community files: LICENSE (Apache-2.0), CONTRIBUTING, SECURITY policy, issue/PR templates
- Release workflow publishing container images to GHCR and packages to npm/PyPI on version tags
- Static landing page (`site/`)

Initial changelog entry. Pre-existing surface:

### Added

- Fail-closed authorization core (Rust) with policy invariants and runtime modes
- Transparent STARK proofs over action logs (ZK verifier + SDK)
- Call-signature v2 request binding across TS, Python, and Go clients
- Multi-tenancy with isolation tests and tenant-scoped audit
- Agent egress gateway with SSRF protection
- Passwordless user authentication
- Hash-chained audit log with Bitcoin/Solana anchoring
- Differential-privacy stats aggregation with integrity proofs
- Next.js operator dashboard (activity, agents, revocation, scenarios)
- Postgres backend port alongside SQLite
- Security CI: cargo-audit, cargo-deny, gitleaks, trivy, weekly audit, SBOM
