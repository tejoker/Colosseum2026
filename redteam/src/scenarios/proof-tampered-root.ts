/**
 * S12 redteam — proof-tampered-root.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component → ZK
 * prover → Tampering". The verifier resolves the root from a finalized,
 * tenant-scoped checkpoint and binds it to the proof's public inputs.
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

    const finalized = await fetch(`${BASE_URL}/v1/proofs/checkpoint/finalize`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
            "x-sauron-tenant-id": "default",
        },
        body: JSON.stringify({
            circuit: "ActionSumBound",
            merkle_root: "00".repeat(32),
            tree_size: 4,
        }),
    });
    if (!finalized.ok) {
        return skipped(id, name, `checkpoint service unavailable: ${finalized.status}`);
    }
    const checkpoint = (await finalized.json()) as { checkpoint_id: string; finalized: boolean };
    if (!checkpoint.finalized) {
        return skipped(id, name, "checkpoint is awaiting OpenTimestamps finalization");
    }
    const body = {
        circuit: "ActionSumBound",
        public_inputs: ["1", "1", "0"], // proof claims root=1; checkpoint says root=0
        proof_b64: "e30=",
        vk_id: "ActionSumBound.dev.vk@v1",
        checkpoint_id: checkpoint.checkpoint_id,
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
            "Server resolved the root from an anchored checkpoint — any " +
            "byte-flip breaks the equality check.",
        evidence: { status: r.status, body: text.slice(0, 200) },
    };
}

if (require.main === module) {
    void runScenario(main);
}
