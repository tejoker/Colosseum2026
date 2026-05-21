/**
 * S3 redteam — tenant-spend-ledger-race.
 *
 * Threat model: docs/threat-model.md "Tampering → spend ledger
 * collision". When tenant A and tenant B share an agent_id (same
 * logical agent name registered under both tenants), concurrent
 * POST /spend calls MUST land in separate ledger rows keyed by
 * (tenant_id, agent_id, policy_id, period_start). No cross-tenant
 * collision is allowed.
 *
 * Scenario:
 *   1. As tenant A and tenant B, in parallel, POST /spend for the
 *      same agent_id + policy_id (amounts 1.0 from A, 100.0 from B).
 *   2. Read each tenant's ledger; assert they see only their own
 *      total, never each other's.
 *
 * Mitigation in code:
 *   - core/src/db.rs spend_ledger PRIMARY KEY (policy_id, agent_id,
 *     period_start) + tenant_id column scoped via repository helpers.
 *   - core/src/policy/handlers.rs record_spend_inner_tenant uses
 *     the tenant filter on all upserts.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function recordSpend(
    tenant: string,
    agentId: string,
    policyId: string,
    amount: number,
): Promise<number> {
    const r = await fetch(`${BASE_URL}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenant,
        },
        body: JSON.stringify({ policy_id: policyId, amount_usd: amount }),
    });
    return r.status;
}

async function getSpend(
    tenant: string,
    agentId: string,
    policyId: string,
): Promise<{ status: number; total: number | null }> {
    const r = await fetch(
        `${BASE_URL}/v1/agents/${agentId}/spend?policy_id=${encodeURIComponent(policyId)}`,
        {
            headers: {
                authorization: `Bearer ${ADMIN_KEY!}`,
                "x-sauron-tenant-id": tenant,
            },
        },
    );
    let total: number | null = null;
    if (r.ok) {
        try {
            const data = (await r.json()) as { total_usd?: number };
            total = data.total_usd ?? null;
        } catch {
            total = null;
        }
    }
    return { status: r.status, total };
}

async function main(): Promise<ScenarioResult> {
    const id = "T14";
    const name = "tenant-spend-ledger-race";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;
    const agentId = `agt_race_${Date.now()}`;
    const policyId = `pol_race_${Date.now()}`;

    // Race: parallel writes from both tenants.
    const burst = 10;
    const writes: Promise<number>[] = [];
    for (let i = 0; i < burst; i++) {
        writes.push(recordSpend(tenantA, agentId, policyId, 1.0));
        writes.push(recordSpend(tenantB, agentId, policyId, 100.0));
    }
    const statuses = await Promise.all(writes);
    const okCount = statuses.filter((s) => s === 200).length;

    const sumA = await getSpend(tenantA, agentId, policyId);
    const sumB = await getSpend(tenantB, agentId, policyId);

    // Each tenant's total must reflect only their own contributions.
    // If sums overlap (sumA.total >= 100 or sumB.total includes A's 1.0
    // contributions in sub-burst), collision happened.
    const totalA = sumA.total ?? 0;
    const totalB = sumB.total ?? 0;
    const aBounded = totalA <= burst * 1.0 + 1e-6;
    const bBounded = totalB >= burst * 100.0 - 1e-6 && totalB <= burst * 100.0 + 1e-6;
    const pass = aBounded && bBounded;

    return {
        id,
        name,
        pass,
        note:
            "Concurrent cross-tenant spend on same (agent, policy) must land in " +
            "separate ledger rows. Tenant A total bounded by its own contributions; " +
            "Tenant B total bounded by its own. Mitigation: spend_ledger composite PK + " +
            "tenant_id column.",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            agent_id: agentId,
            policy_id: policyId,
            successful_writes: okCount,
            tenant_a_total: totalA,
            tenant_b_total: totalB,
            a_bounded: aBounded,
            b_bounded: bBounded,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
