/**
 * S12 redteam — proof-stale-period.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component →
 * core → Tampering" — sub-case for stats submissions with ancient
 * period_start.
 *
 * Production defaults reject period_end older than 14 days, periods longer
 * than 8 days, and period_end more than five minutes in the future.
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
    const id = "P5";
    const name = "proof-stale-period";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenant = `t-stale-${Date.now()}`;
    const sixMonthsAgo = Math.floor(Date.now() / 1000) - 6 * 30 * 24 * 3600;
    const checkpointResponse = await fetch(`${BASE_URL}/v1/proofs/checkpoint/finalize`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
            "x-sauron-tenant-id": tenant,
        },
        body: JSON.stringify({
            circuit: "StatsHonestComputation",
            merkle_root: "00".repeat(32),
            tree_size: 100,
        }),
    });
    if (!checkpointResponse.ok) {
        return skipped(id, name, `checkpoint service unavailable: ${checkpointResponse.status}`);
    }
    const checkpoint = (await checkpointResponse.json()) as {
        checkpoint_id: string;
        finalized: boolean;
    };
    if (!checkpoint.finalized) {
        return skipped(id, name, "checkpoint is awaiting OpenTimestamps finalization");
    }

    const submission = {
        tenant_id: tenant,
        metric_id: "success_rate",
        claimed_value: 950,
        n_records: 100,
        period_start: sixMonthsAgo,
        period_end: sixMonthsAgo + 3600,
        merkle_root: "00".repeat(32),
        proof_b64: "e30=",
        vk_id: "StatsHonestComputation.dev.vk@v1",
        checkpoint_id: checkpoint.checkpoint_id,
        public_inputs: ["0", "0", "0"],
    };
    const r = await fetch(`${BASE_URL}/v1/stats/submit`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
            "x-sauron-tenant-id": tenant,
        },
        body: JSON.stringify(submission),
    });
    const text = await r.text();

    const rejected = r.status === 400 && text.toLowerCase().includes("stale");
    const accepted = r.status >= 200 && r.status < 300;

    return {
        id,
        name,
        pass: rejected,
        note:
            "Stale-period submissions must be rejected before proof verification in production.",
        evidence: {
            status: r.status,
            period_start_sec_ago: Math.floor(Date.now() / 1000) - sixMonthsAgo,
            server_accepted: accepted,
            body: text.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
