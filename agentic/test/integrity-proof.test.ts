/**
 * Sprint 7 — integrity-proof envelope + error-surface tests.
 *
 * Skips the real snarkjs witness gen (no DEV ceremony required) by feeding
 * a stub proofRunner. Asserts the envelope shape + the error surface for
 * non-provable metrics + length-mismatched merkle proofs.
 */

import {
    StatsProver,
    NotProvableError,
    receiptToFields,
    MAX_RECEIPTS_PER_PROOF,
    type ProofRunner,
} from "../src/stats/integrity-proof";
import { LocalAggregator, type ReceiptLike } from "../src/stats/local-aggregate";

let passed = 0;
let failed = 0;
function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

const stubProof = {
    pi_a: ["1"],
    pi_b: [["1"]],
    pi_c: ["1"],
    protocol: "groth16",
    curve: "bn128",
};

function stubRunner(): ProofRunner {
    return async ({ witness }) => {
        // Echo back the public-input portion of the witness so the test can
        // assert envelope binding.
        const publicSignals = [
            "1",
            witness.root as string,
            witness.metric_id as string,
            witness.claimed_value as string,
            witness.n_records as string,
            witness.period_start as string,
            witness.period_end as string,
        ];
        return { proof: stubProof, publicSignals };
    };
}

function mkReceipt(over: Partial<ReceiptLike> = {}): ReceiptLike {
    return {
        receipt_id: "r1",
        action_hash: "h1",
        agent_id: "agent-A",
        status: "ok",
        tool: "echo",
        created_at: 100,
        ...over,
    };
}

function dummyPaths(n: number) {
    return Array.from({ length: n }, () => ({
        pathElements: ["0", "0"],
        pathIndices: [0, 0],
    }));
}

async function testHappyPath() {
    console.log("\n═══ proveStat: happy path (mocked runner) ═══");
    const receipts = [
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "denied" }),
        mkReceipt({ status: "ok" }),
    ];
    const agg = new LocalAggregator({
        receipts,
        periodStart: 0,
        periodEnd: 1000,
    });
    const m = agg.compute("success_rate");

    const prover = new StatsProver({
        circuitsDir: "/unused",
        proofRunner: stubRunner(),
    });
    const out = await prover.proveStat(m, receipts, dummyPaths(receipts.length), "deadbeef");

    assert(out.circuit === "StatsHonestComputation", "envelope.circuit set");
    assert(out.root === "deadbeef", "root passes through");
    assert(out.metric.id === "success_rate", "metric echoed");
    assert(
        out.public_inputs.length === 7,
        `7 public inputs (valid+root+metric_id+claimed+n_records+start+end), got ${out.public_inputs.length}`,
    );
    assert(out.public_inputs[2] === "0", "metric_id index = 0 (success_rate)");
    assert(out.public_inputs[3] === String(m.value_fixed), "claimed_value matches");
    assert(out.public_inputs[4] === "4", "n_records = 4");
    assert(out.proof === stubProof, "proof object passes through");
}

async function testNonProvableErrors() {
    console.log("\n═══ proveStat: NotProvableError on percentile ═══");
    const receipts = [mkReceipt({ latency_ms: 100 })];
    const m = new LocalAggregator({
        receipts,
        periodStart: 0,
        periodEnd: 1000,
    }).compute("latency_p50");

    const prover = new StatsProver({
        circuitsDir: "/unused",
        proofRunner: stubRunner(),
    });
    let caught: unknown = null;
    try {
        await prover.proveStat(m, receipts, dummyPaths(receipts.length), "00");
    } catch (e) {
        caught = e;
    }
    assert(caught instanceof NotProvableError, "throws NotProvableError on percentile");
    if (caught instanceof NotProvableError) {
        assert(caught.metricId === "latency_p50", "metricId echoed on error");
    }
}

async function testEmptyAndOversized() {
    console.log("\n═══ proveStat: empty + oversized rejection ═══");
    const prover = new StatsProver({
        circuitsDir: "/unused",
        proofRunner: stubRunner(),
    });
    const dummyMetric = {
        id: "success_rate" as const,
        value: 0,
        value_fixed: 0,
        n_records_used: 0,
        period: { start: 0, end: 0 },
    };

    // Empty receipts
    let caught: unknown = null;
    try {
        await prover.proveStat(dummyMetric, [], [], "0");
    } catch (e) {
        caught = e;
    }
    assert(caught instanceof Error, "empty receipts rejected");

    // Over the cap
    const big = Array.from({ length: MAX_RECEIPTS_PER_PROOF + 1 }, () => mkReceipt());
    caught = null;
    try {
        await prover.proveStat(
            dummyMetric,
            big,
            dummyPaths(big.length),
            "0",
        );
    } catch (e) {
        caught = e;
    }
    assert(
        caught instanceof Error && /exceeds circuit cap/.test((caught as Error).message),
        "over-cap rejected with explicit cap message",
    );
}

async function testLengthMismatch() {
    console.log("\n═══ proveStat: receipts/proofs length mismatch ═══");
    const receipts = [mkReceipt(), mkReceipt(), mkReceipt()];
    const proofs = dummyPaths(2); // off-by-one
    const prover = new StatsProver({
        circuitsDir: "/unused",
        proofRunner: stubRunner(),
    });
    const m = new LocalAggregator({
        receipts,
        periodStart: 0,
        periodEnd: 1000,
    }).compute("success_rate");
    let caught: unknown = null;
    try {
        await prover.proveStat(m, receipts, proofs, "0");
    } catch (e) {
        caught = e;
    }
    assert(
        caught instanceof Error && /merkleProofs/.test((caught as Error).message),
        "length mismatch rejected",
    );
}

async function testReceiptToFieldsDeterministic() {
    console.log("\n═══ receiptToFields: deterministic projection ═══");
    const r = mkReceipt({ status: "ok", latency_ms: 50, amount_usd: 1.5 });
    const a = receiptToFields(r);
    const b = receiptToFields(r);
    assert(a.length === 6, `6 fields per receipt (got ${a.length})`);
    assert(a.every((x, i) => x === b[i]), "deterministic across calls");
    assert(a[0] === "1", "status_bit = 1 for ok");
    assert(a[1] === "50", "latency_ms = 50");
    assert(a[2] === "1500", "amount in milli-USD = 1500");
}

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  SauronID — Sprint 7 StatsProver tests          ║");
    console.log("╚══════════════════════════════════════════════════╝");
    try {
        await testHappyPath();
        await testNonProvableErrors();
        await testEmptyAndOversized();
        await testLengthMismatch();
        await testReceiptToFieldsDeterministic();

        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");
        if (failed > 0) process.exit(1);
    } catch (e) {
        const err = e as Error;
        console.error("\n  ✗ FATAL:", err.message);
        console.error(err.stack);
        process.exit(1);
    }
}

void main();
