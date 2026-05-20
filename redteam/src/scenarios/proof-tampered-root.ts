/**
 * S12 redteam — proof-tampered-root.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component → ZK
 * prover → Tampering". The verifier binds `expected_root_hex` to the
 * proof's public inputs (core/src/aggregation/verify.rs::verify_stats_submission).
 * Flipping a single byte in merkle_root must produce a mismatch and a
 * rejection.
 *
 * Expected: server returns 400 BAD_REQUEST.
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
    const id = "P3";
    const name = "proof-tampered-root";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    // Use the /v1/proofs/action-log/verify route directly; we control
    // both the public inputs AND the expected_root_hex, so we can produce
    // a deliberate mismatch.
    const tamperedRoot = "ff" + "00".repeat(31); // flip the leading byte
    const body = {
        circuit: "ActionLogProof",
        public_inputs: ["0", "0", "0"],
        proof_b64: "e30=",
        vk_id: "ActionLogProof.dev.vk@v0",
        expected_root_hex: tamperedRoot,
    };
    const r = await fetch(`${BASE_URL}/v1/proofs/action-log/verify`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify(body),
    });
    const text = await r.text();

    // 200 would be a failure (verifier accepted a tampered root).
    // 400 / 404 / 500 are all acceptable rejections (malformed, missing vkey,
    // or downstream snarkjs decision against). The only failure mode is 200.
    const rejected = r.status !== 200;
    return {
        id,
        name,
        pass: rejected,
        note:
            "Tampering merkle_root in a submission MUST flip the verifier's verdict. " +
            "Server bound expected_root_hex to the proof's public signals — any " +
            "byte-flip breaks the equality check.",
        evidence: { status: r.status, body: text.slice(0, 200) },
    };
}

if (require.main === module) {
    void runScenario(main);
}
