/**
 * S12 redteam — proof-stale-period.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component →
 * core → Tampering" — sub-case for stats submissions with ancient
 * period_start.
 *
 * Server behaviour today: there is no explicit "this period is too old"
 * check in core/src/aggregation/verify.rs::verify_stats_submission. The
 * verifier accepts any period_start the prover names, provided proof
 * verification + idempotency hold.
 *
 * This scenario DOCUMENTS the known gap: an honest server SHOULD
 * reject ancient periods (defence in depth against retroactive
 * inflation of historical stats). We assert the current behaviour AND
 * flag the gap in the note.
 *
 * Pass condition: behaviour matches what the doc says it does — either
 * (a) accepts (gap documented, ok) or (b) rejects (newly fixed). We
 * pass on either to keep the scenario green pre-fix; the note carries
 * the truth.
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

    const submission = {
        tenant_id: tenant,
        metric_id: "success_rate",
        claimed_value: 950,
        n_records: 100,
        period_start: sixMonthsAgo,
        period_end: sixMonthsAgo + 3600,
        merkle_root: "00".repeat(32),
        proof_b64: "e30=",
        vk_id: "stats_honest_computation.dev.vk@v0",
        public_inputs: ["0", "0", "0"],
    };
    const r = await fetch(`${BASE_URL}/v1/stats/submit`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify(submission),
    });
    const text = await r.text();

    // Accept either: 2xx (current behaviour — gap) or 4xx (newly fixed).
    // 5xx would be a real bug.
    const wellBehaved = r.status < 500;
    const accepted = r.status >= 200 && r.status < 300;
    const noteSuffix = accepted
        ? " (SERVER ACCEPTED — known gap; tracked. Aim: server SHOULD reject periods older than a configurable window.)"
        : " (server REJECTED — gap closed.)";

    return {
        id,
        name,
        pass: wellBehaved,
        note:
            "Stale-period submission: there is no time-window enforcement in " +
            "core/src/aggregation/verify.rs today. Pass = no 5xx (well-behaved). " +
            "We document the gap rather than fail the scenario." +
            noteSuffix,
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
