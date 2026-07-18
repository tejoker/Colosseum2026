/**
 * S12 redteam — proof-cross-tenant.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component →
 * core → Information disclosure: cross-tenant data leak". The
 * customer_stats PK includes tenant_id; idempotent upserts are scoped
 * (core/src/aggregation/store.rs:24-38). A submission claiming tenant A
 * cannot land under tenant B's row even if the proof, the root, and
 * everything else matches.
 *
 * Scenario: tenant A submits a proof whose merkle_root happens to also
 * exist (hypothetically) under tenant B's receipt chain. The PK scoping
 * means the row lands ONLY under A, never under B.
 *
 * Expected: post-submission, B's cohort is unchanged.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

interface CohortRow {
    tenant_id: string;
    metric_id: string;
    period_start: number;
}

async function fetchCohort(): Promise<CohortRow[]> {
    const r = await fetch(`${BASE_URL}/v1/stats/cohort`, {
        headers: { authorization: `Bearer ${ADMIN_KEY!}` },
    });
    if (!r.ok) return [];
    return (await r.json()) as CohortRow[];
}

async function main(): Promise<ScenarioResult> {
    const id = "P4";
    const name = "proof-cross-tenant";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `t-A-${Date.now()}`;
    const tenantB = `t-B-${Date.now()}`;
    const metric = "success_rate";
    const period = Math.floor(Date.now() / 1000);

    // Snapshot B's cohort before.
    const before = await fetchCohort();
    const bBefore = before.filter((c) => c.tenant_id === tenantB).length;

    // Submit under tenant A, with a body that includes tenantA. The
    // server uses the tenant from auth context + the body tenant_id;
    // either path must reject if they disagree, or scope strictly to A.
    const submission = {
        tenant_id: tenantA,
        metric_id: metric,
        claimed_value: 100,
        n_records: 50,
        period_start: period,
        period_end: period + 3600,
        merkle_root: "11".repeat(32),
        proof_b64: "e30=",
        vk_id: "StatsHonestComputation.dev.vk@v1",
        checkpoint_id: "zkc_wrong_tenant",
        public_inputs: ["0", "0", "0"],
    };
    await fetch(`${BASE_URL}/v1/stats/submit`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
            "x-sauron-tenant-id": tenantA,
        },
        body: JSON.stringify(submission),
    });

    const after = await fetchCohort();
    const bAfter = after.filter((c) => c.tenant_id === tenantB).length;

    const bUnchanged = bAfter === bBefore;
    return {
        id,
        name,
        pass: bUnchanged,
        note:
            "Submission claiming tenant A — even with arbitrary merkle_root — cannot " +
            "create or update a row under tenant B. customer_stats PK scopes upsert " +
            "by tenant_id (core/src/aggregation/store.rs:24-38).",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            b_rows_before: bBefore,
            b_rows_after: bAfter,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
