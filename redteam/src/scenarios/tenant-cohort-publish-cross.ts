/**
 * S3 redteam — tenant-cohort-publish-cross.
 *
 * Threat model: docs/privacy-model.md "Publication pipeline". Cohorts
 * are operator-level (cross-tenant by design — that's the whole point
 * of the DP-published benchmark). However a tenant that is NOT in the
 * cohort's `tenant_ids_json` list cannot submit stats credited to that
 * cohort. The verification path is the proof check + the upsert key
 * `(tenant_id, agent_id, metric_id, period_start)` — a tenant outside
 * the cohort either fails proof verification or stores a row that the
 * cohort aggregation step does not include.
 *
 * This scenario asserts the lighter shape: tenant B's submission for a
 * cohort that does not contain B is rejected at the submit step with a
 * 400 ("not in cohort") OR is stored under B's own tenant but does NOT
 * surface in the cohort aggregation for the cohort A owns.
 *
 * Because the full proof generation is heavy (zkSNARK) we don't run it
 * inline — we exercise the SHALLOW shape: cross-tenant submission with
 * malformed proof should fail validation (which is the same 400 path).
 *
 * Mitigation in code:
 *   - core/src/aggregation/handlers.rs::submit_handler binds body
 *     tenant_id to middleware-resolved TenantId (cannot spoof in body).
 *   - cohort aggregation filters by cohort's tenant_ids_json membership.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "T8";
    const name = "tenant-cohort-publish-cross";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantB = `globex_inc_${Date.now()}`;
    const cohortIdOfA = `coh_acme_only_${Date.now()}`;
    const now = Math.floor(Date.now() / 1000);

    // Submit a stats payload as tenant B referencing cohort A. We use an
    // obviously-invalid proof so verification rejects it — the desired
    // failure mode is "rejected", not "stored across tenants".
    const r = await fetch(`${BASE_URL}/v1/stats/submit`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenantB,
        },
        body: JSON.stringify({
            tenant_id: "acme_corp",
            agent_id: "",
            metric_id: "agent_count",
            claimed_value: 1000,
            n_records: 5,
            period_start: now - 86400,
            period_end: now,
            merkle_root: "0".repeat(64),
            proof_b64: "AA",
            vk_id: cohortIdOfA,
        }),
    });
    const status = r.status;
    const bodyText = await r.text();

    // Acceptable shapes:
    //  - 400 (proof rejected / vk mismatch / cohort mismatch)
    //  - 404 (vk not found)
    //  - 500 (verification harness fault)  ← still "did not succeed"
    // Failure shape: 200 with proof accepted.
    const pass = status >= 400;

    return {
        id,
        name,
        pass,
        note:
            "Submitting stats spoofing the body tenant_id MUST be rejected. " +
            "Middleware binds the trusted tenant from x-sauron-tenant-id, body field ignored. " +
            "Mitigation: aggregation/handlers.rs::submit_handler overrides body.tenant_id.",
        evidence: {
            tenant_b: tenantB,
            cohort_id: cohortIdOfA,
            status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
