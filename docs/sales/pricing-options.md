# Pricing options — INTERNAL

**INTERNAL decision document. Do not share outside the founding team. Nothing here is a public commitment.**

## The tension, stated plainly

SauronID is Apache-2.0, whole product. Anyone — including every prospect we pitch — can self-host it free, forever, with no feature gate. That is also the pitch: "if we disappear, your deployment keeps running" and "verify the audit trail without trusting us" only work because the code is open. So the question is not "how do we stop free usage" (we can't, and trying would kill the differentiator) but "what do people pay for that the tarball does not contain?"

What the tarball does not contain: someone on the hook for uptime, someone maintaining the crypto and rotating the anchors, someone answering the security questionnaire with a signature, SOC 2, and a human who fixes it at 3am. That is the product.

## Option A — managed cloud + SLA/support on top of OSS

Run SauronID as a hosted service; the OSS stays whole and free.

- **Industry examples:** GitLab (gitlab.com vs self-managed), Grafana Cloud, Supabase, PlanetScale-style "the OSS is the funnel, the cloud is the business".
- **Pros:** Cleanest story with Apache-2.0 — no feature hostage-taking, community goodwill intact. Directly monetizes our real weaknesses-as-self-host: the honest limits are single-node ops, backups/restore drills, anchor monitoring, no SOC 2 ([production-readiness](../production-readiness.md)) — a managed offering makes every one of those OUR problem instead of the buyer's, which is exactly what they want to pay to avoid. SOC 2 becomes achievable because we control the perimeter.
- **Cons:** We become an ops company: on-call, multi-tenant infrastructure, and we must actually build the HA we honestly say does not exist yet. Slight tension with "your data never leaves your infra" — mitigated because the gateway can be hosted while receipts stay verifiable by the customer, but some security buyers will insist on self-host anyway (serve them via Option C attached to A).
- **Cost of goods:** real — compute, on-call, compliance audits.

## Option B — open-core: enterprise features paid

Keep the current core Apache-2.0; new enterprise features (SSO/SCIM, compliance packs, HA orchestration, long retention, advanced RBAC) ship under a commercial license.

- **Industry examples:** GitLab EE tiers, Elastic (pre-license-change), Cockroach, Teleport Enterprise.
- **Pros:** Monetizes exactly what enterprises need and hobbyists don't; no ops burden; features like HA orchestration and SSO are on our roadmap anyway and map cleanly to who has budget.
- **Cons:** Direct conflict with our published positioning — the README's honesty tables and "no vendor lock-in" scorecard row are load-bearing sales assets; the moment security features are paywalled, "verify everything yourself" gets an asterisk. Deciding what is core vs paid is a permanent tax and community-trust risk (Elastic's history). Worst fit for us specifically: our differentiator is verifiable security, and the enterprise features buyers want most (HA, SSO) are the ones we'd have to build regardless — gating them earns the resentment without saving the work.
- **Note:** SSO for end-users is already declared out of scope ("remains an integration with the customer's IdP" — [README](../../README.md)); an open-core SSO story would partially reverse a published design position.

## Option C — support + certification subscription only

Everything stays open; sell support contracts, deployment certification, and priority fixes.

- **Industry examples:** Red Hat (the canonical case), Tidelift, early HashiCorp.
- **Pros:** Zero conflict with Apache-2.0; near-zero build cost; matches today's reality (the product needs "a senior week" of integration — [empirical-comparison](../empirical-comparison.md) — so paid help is genuinely valuable now, pre-managed-offering). A "certified deployment review" against the production-readiness checklist is a natural, honest SKU.
- **Cons:** Support-only revenue scales with headcount, not software; deal sizes stay small; buyers increasingly want a hosted thing, not a consultant; Red Hat worked at a scale and era we should not assume. As a sole model it caps the company.

## Recommendation

**Option A as the destination, with Option C attached from day one.** Reasoning:

- The buyer is a security team. What they want from us is the audit trail hosted reliably and the cryptography maintained by its authors — not a feature unlock. Our own honest-limits list (single-node, restore drills, anchor monitoring, no certifications) is literally a description of what a managed offering sells.
- A is the only option under which SOC 2 makes sense to pursue, and "no compliance certs" is currently our top procurement blocker per our own [buyer scorecard](../empirical-comparison.md).
- C is sellable this quarter with zero build: paid pilot support, deployment certification against [production-readiness](../production-readiness.md), and an SLA on security fixes. It funds the runway to A and every C customer is an A lead.
- B is rejected: it undermines the verifiability positioning that is our only real moat against Auth0/AWS, and its flagship features (HA, SSO glue) must be built for A anyway.

### Price anchor — starting hypothesis, NOT market truth

Explicitly a founder-validation starting point, reasoned from comparable dev-infra security tooling (Teleport, Tailscale, Snyk-class deals commonly land in the low-to-mid five figures annually for a first enterprise contract; Auth0-style identity add-ons similar):

- **Design-partner pilot (now):** free to ~5k EUR for the 4 weeks, converting to a support contract; the payment is mostly the quotable result.
- **Support + certification (Option C, now):** 15k-40k EUR/yr per production deployment, tiered by response SLA.
- **Managed (Option A, later):** 2k-5k EUR/mo entry per tenant with usage-based expansion (agents or signed calls), i.e. 25k-60k EUR/yr — sized to sit below the "needs a board-level vendor review" line while beating support-only ACV.

Validate against the first five real conversations before printing any of these numbers anywhere. If prospects negotiate the support tier UP because they need someone accountable, that is the signal A is right; if they only want free self-host plus paid emergencies, revisit C-only sizing.
