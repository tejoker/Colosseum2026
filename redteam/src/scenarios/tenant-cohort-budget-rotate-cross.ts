/**
 * S3 redteam — tenant-cohort-budget-rotate-cross.
 *
 * Threat model: docs/privacy-model.md "Publication pipeline → budget
 * rotation". Cohorts are operator-level (cross-tenant by design) and
 * the ε budget ledger is per-cohort, NOT per-tenant. The rotate
 * endpoint requires the operator admin key but is documented as
 * operator-only — it should NOT be triggerable simply by setting a
 * tenant header. The actual gate is the admin key on the static
 * admin-router; per-tenant scoping is implicit.
 *
 * Scenario:
 *   1. As tenant B (with admin key), try to rotate a cohort id that
 *      was never registered.
 *   2. Assert 404 (cohort not found).
 *
 * Mitigation in code:
 *   - core/src/aggregation/handlers.rs::cohort_budget_rotate_handler
 *     calls `store.get(&id)` which returns None for unknown ids and
 *     surfaces a 404 — the cohort id space itself acts as the
 *     enumeration barrier.
 *   - The admin gate at the router layer prevents non-operator
 *     callers from even reaching the handler.
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
    const id = "T15";
    const name = "tenant-cohort-budget-rotate-cross";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantB = `globex_inc_${Date.now()}`;
    const cohortId = `coh_owned_by_a_${Date.now()}`;

    const now = Math.floor(Date.now() / 1000);
    const r = await fetch(`${BASE_URL}/v1/cohort/${cohortId}/budget/rotate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenantB,
        },
        body: JSON.stringify({
            new_cycle_start: now,
            new_epsilon_cap: 1.0,
            new_delta_cap: 1e-6,
        }),
    });
    const status = r.status;
    const bodyText = await r.text();

    const pass = status === 404;
    return {
        id,
        name,
        pass,
        note:
            "Cohort rotate for unknown id MUST 404. Cohorts are operator-level " +
            "(shared id space) — the existence check is the only barrier needed " +
            "since the cohort id is itself the gating capability. Mitigation: " +
            "aggregation/handlers.rs::cohort_budget_rotate_handler store.get + NotFound.",
        evidence: {
            tenant_b: tenantB,
            cohort_id: cohortId,
            status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
