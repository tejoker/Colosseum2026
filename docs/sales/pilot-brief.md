# SauronID design-partner pilot — 4 weeks

## Who this is for

Teams putting LLM agents against real systems: internal APIs, customer-facing APIs, payments, or agent-to-agent traffic — anywhere a prompt-injected agent with valid credentials can do real damage. You should have at least one agent flow in staging or production and an engineer who can spend a few hours per week. You keep everything in your infrastructure; SauronID is self-hosted (Apache-2.0), so the pilot needs no data-sharing agreement for your traffic.

Not a fit (we will say so on the first call): teams needing HA/multi-region today, teams whose procurement requires SOC 2 from the vendor now, or traffic that cannot be routed through a gateway. See [production-readiness](../production-readiness.md) for the deployment truth.

## The 4 weeks

**Week 1 — deploy alongside one agent, advisory mode.**
Stand up SauronID next to one existing agent (`docker compose`, Helm, or native systemd — [deploy/README.md](../../deploy/README.md)). Register the agent through the SDK or MCP server; run in advisory mode, which logs call-signature violations without blocking. Exit: signed calls flowing, dashboard showing live traffic, zero behavior change for the agent.

**Week 2 — policies and fail-closed on one flow.**
Write intent and egress policies for one real flow (host/method/path constraints, byte and rate caps, one-use capabilities where it fits) and flip that flow to fail-closed (`SAURON_REQUIRE_CALL_SIG=1`). Wire the audit JSONL into your SIEM ([config, not a project](../siem-integration.md)). Exit: one production-shaped flow enforced, false-positive rate known.

**Week 3 — red-team replay against YOUR deployment.**
Run the 16-attack empirical suite ([redteam/](../../redteam/)) pointed at your instance: replay, body tampering, cross-endpoint reuse, revoked-agent, delegation scope creep, config drift, and the rest. Then improvise — your team tries to get the agent to misbehave through prompt injection while the gateway is in the way. Exit: your own attack log, with each attempt's rejection receipt.

**Week 4 — receipts, audit review, go/no-go.**
Walk the audit trail with your security team: hash-chain verification, anchored batches checked externally with `ots verify`, STARK statement verification against published image IDs. Joint go/no-go: expand to more agents, or a written list of what would have to change first. Exit: decision memo, both sides keep a copy.

## What we ask from you

- A weekly 30-minute check-in and honest feedback, including where it hurt.
- One named engineer as the integration contact.
- At the end, if the pilot met its criteria: a quotable result (attack numbers from your week-3 run, or a short reference statement) — reviewed and approved by you before any use.

## What you get

- Hands-on support from the people who wrote the code: integration help, policy authoring, same-week fixes for pilot-blocking bugs.
- Direct influence on the roadmap — design partners set the priority order for Postgres/HA, enterprise auth integration, and retention features.
- Locked pricing: whatever commercial terms exist when the pilot converts are held for you for 12 months.
- All of it on your infrastructure, under Apache-2.0 — if we disappear tomorrow, your deployment keeps running.

## Success criteria (agreed in week 1, checked in week 4)

- [ ] One real agent flow running fail-closed in a production-like environment.
- [ ] 16/16 attack suite blocked against the partner's own deployment.
- [ ] At least one improvised injection attempt rejected with a receipt.
- [ ] Audit trail flowing into the partner's SIEM; chain-head verification passes.
- [ ] At least one anchored batch externally verified (`ots verify` or Solana explorer).
- [ ] False-positive count on the enforced flow at an agreed threshold (target: zero after policy tuning).
- [ ] Latency overhead on the enforced flow measured and within the agreed budget (single-node reference: p50 2 ms, p99 8 ms at concurrency 1 — [benchmarks](../empirical-comparison.md)).
- [ ] Security team has read the [threat model](../threat-model.md) and agrees the documented limits are acceptable for the pilot scope.

Contact: open an issue on the repository or use the contact route in [SECURITY.md](../../SECURITY.md) for anything sensitive.
