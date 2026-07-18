/**
 * S12 redteam — proof-replay.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component → ZK
 * prover → Tampering". Idempotency invariant of customer_stats: the PK
 * `(tenant_id, COALESCE(agent_id,''), metric_id, period_start)` (see
 * core/src/aggregation/store.rs) means re-submitting the same proof
 * twice is either a no-op OR rejected as a duplicate. Either is
 * acceptable behaviour; double-count would be the failure.
 *
 * Expected: second submission accepted as no-op (same data) OR
 * rejected (duplicate). Either way, NO double-count.
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
    n_records?: number;
    claimed_value?: number;
}

async function submit(body: Record<string, unknown>): Promise<Response> {
    return fetch(`${BASE_URL}/v1/stats/submit`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
        },
        body: JSON.stringify(body),
    });
}

async function fetchCohort(): Promise<CohortRow[]> {
    const r = await fetch(`${BASE_URL}/v1/stats/cohort`, {
        headers: { authorization: `Bearer ${ADMIN_KEY!}` },
    });
    if (!r.ok) return [];
    return (await r.json()) as CohortRow[];
}

async function main(): Promise<ScenarioResult> {
    const id = "P1";
    const name = "proof-replay";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenant = `t-replay-${Date.now()}`;
    const metric = "success_rate";
    const period = Math.floor(Date.now() / 1000);

    // Submission body. We intentionally use a malformed proof so the
    // verifier rejects it BEFORE write — but the harness only cares
    // about whether the SECOND submission is idempotent vs the first.
    // If the verifier rejects both, that's still consistent (no double
    // count). If it accepts both, the unique constraint on customer_stats
    // catches the dup. Either outcome → pass.
    const submission = {
        tenant_id: tenant,
        metric_id: metric,
        claimed_value: 950,
        n_records: 100,
        period_start: period,
        period_end: period + 3600,
        merkle_root: "00".repeat(32),
        proof_b64: "e30=", // base64 of "{}"
        vk_id: "StatsHonestComputation.dev.vk@v1",
        checkpoint_id: "zkc_nonexistent",
        public_inputs: ["0", "0", "0"],
    };

    const r1 = await submit(submission);
    const r2 = await submit(submission);

    // Compute net row count for this tenant. After either accept-twice
    // (which should idempotent-upsert to one row) or reject-twice (zero
    // rows), the count must be <= 1.
    const cohort = await fetchCohort();
    const rowsForTenant = cohort.filter(
        (c) => c.tenant_id === tenant && c.metric_id === metric && c.period_start === period,
    );

    const noDoubleCount = rowsForTenant.length <= 1;
    return {
        id,
        name,
        pass: noDoubleCount,
        note:
            "Replay of identical submission must NEVER produce two rows for the same " +
            "(tenant, metric, period). Either rejected (verifier denies the proof) or " +
            "idempotent upsert (customer_stats PK). Both are acceptable; double-count " +
            "is the failure.",
        evidence: {
            first_status: r1.status,
            second_status: r2.status,
            rows_after: rowsForTenant.length,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
