/**
 * S12 redteam — proof-wrong-vk.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component → ZK
 * prover → Spoofing". The verifier loads the vkey from the catalog
 * keyed by `circuit`; the submission's `vk_id` is metadata for
 * key-rotation observability (core/src/zk_verifier.rs:44).
 *
 * Scenario: submit a proof tagged with a vk_id that does NOT match any
 * loaded verification key. Expected: 400 BAD_REQUEST (malformed) or 404
 * (vkey missing) — depending on whether the circuit field itself is
 * unrecognised.
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
    const id = "P2";
    const name = "proof-wrong-vk";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    // Use /v1/proofs/action-log/verify which takes circuit + public_inputs
    // + proof_b64 + vk_id + expected_root_hex.
    const body = {
        circuit: "ThisCircuitDoesNotExist",
        public_inputs: ["0"],
        proof_b64: "e30=",
        vk_id: "made-up-vk.vk@v999",
        expected_root_hex: "00".repeat(32),
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

    const rejected = r.status === 400 || r.status === 404;
    return {
        id,
        name,
        pass: rejected,
        note:
            "Submitting under a circuit/vk_id the verifier does not know MUST be " +
            "rejected. 400 (malformed) or 404 (vkey missing) are both acceptable. " +
            "200 here would mean the verifier accepts whatever vk the prover names — " +
            "a forgery primitive.",
        evidence: { status: r.status, body: text.slice(0, 200) },
    };
}

if (require.main === module) {
    void runScenario(main);
}
