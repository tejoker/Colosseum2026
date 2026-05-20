/**
 * Sprint 7 — ZK integrity-proof generator.
 *
 * Bridges the local aggregator (`local-aggregate.ts`) and the existing
 * snarkjs subprocess pattern (`zkp/sdk/src/action-log.ts`). For each provable
 * metric, it constructs the witness inputs, calls into the action-log SDK,
 * and returns the standard ZK envelope.
 *
 * **Provable subset.** Only metrics with `zk_provable = true` in the catalog
 * are accepted. Percentile + distinct-cardinality metrics raise `NotProvableError`;
 * the caller is expected to either skip them or submit via the trusted-input
 * path with a clearly-labelled WARNING (Sprint 8 cohort.rs handles labelling).
 *
 * **Mockable proof step.** When `proofRunner` is supplied, the snarkjs call
 * is bypassed — used by the test suite to assert the envelope shape + error
 * surface without depending on the DEV ceremony output.
 */

import {
    METRICS,
    METRIC_ID_INDEX,
    type MetricId,
} from "./metric-catalog";
import type { MetricValue, ReceiptLike } from "./local-aggregate";

// ════════════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════════════

/** Merkle inclusion proof for one receipt — same shape as the action-log SDK. */
export interface MerkleProof {
    pathElements: string[];
    pathIndices: number[];
}

/** snarkjs Groth16 proof object. Mirrors `ActionLogProof.proof`. */
export interface ProofObject {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
}

/** Full envelope shipped to the server's `/v1/stats/submit` endpoint. */
export interface StatsHonestProof {
    circuit: "StatsHonestComputation";
    public_inputs: string[];
    proof: ProofObject;
    root: string;
    metric: MetricValue;
}

/** Raised when the caller asks for a proof of a metric whose ZK shape is
 *  not yet implemented (percentiles, distinct counts). */
export class NotProvableError extends Error {
    constructor(public readonly metricId: MetricId) {
        super(`metric ${metricId} is not ZK-provable in StatsHonestComputation (Sprint 7)`);
        this.name = "NotProvableError";
    }
}

/** Pluggable proof runner — the production runner shells out to snarkjs via
 *  the zkp/sdk action-log helpers; tests pass a deterministic stub. */
export type ProofRunner = (input: ProofRunnerInput) => Promise<{
    proof: ProofObject;
    publicSignals: string[];
}>;

export interface ProofRunnerInput {
    circuit: "StatsHonestComputation";
    circuitsDir: string;
    witness: Record<string, string | string[] | string[][]>;
}

/** Options for the StatsProver. */
export interface StatsProverOptions {
    /** Directory holding the compiled circuit artefacts. Default matches the
     *  action-log convention used elsewhere in the codebase. */
    circuitsDir: string;
    /** Override for the proof runner (used by tests). When unset, the default
     *  runner shells out to snarkjs via `zkp/sdk/src/action-log.ts`. */
    proofRunner?: ProofRunner;
}

// ════════════════════════════════════════════════════════════════════════
// Default snarkjs-backed runner
// ════════════════════════════════════════════════════════════════════════

/**
 * Default runner. Lazily imports the zkp/sdk action-log helpers so consumers
 * of the agentic package don't drag snarkjs into their bundle unless they
 * actually call `proveStat`.
 *
 * Production extension point: when the ZK SDK adds a first-class
 * `proveStatsHonest` method, this thin wrapper switches to that call without
 * touching the rest of the agentic surface.
 */
async function defaultProofRunner(input: ProofRunnerInput): Promise<{
    proof: ProofObject;
    publicSignals: string[];
}> {
    // Dynamic require so the snarkjs dependency is optional at module-load
    // time. The zkp/sdk module sits outside agentic's rootDir; we resolve
    // it via a Node require to keep the TS rootDir clean.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const dynamicRequire: NodeRequire = eval("require");
    const sdkPath = require("path").resolve(
        __dirname,
        "..",
        "..",
        "..",
        "zkp",
        "sdk",
        "src",
        "action-log",
    );
    const sdk = dynamicRequire(sdkPath) as {
        proveStatsHonest?: (
            circuitsDir: string,
            witness: Record<string, string | string[] | string[][]>,
        ) => Promise<{ proof: ProofObject; publicSignals: string[] }>;
    };
    if (!sdk.proveStatsHonest) {
        throw new Error(
            "zkp/sdk does not yet expose proveStatsHonest — pass a custom proofRunner",
        );
    }
    return sdk.proveStatsHonest(input.circuitsDir, input.witness);
}

// ════════════════════════════════════════════════════════════════════════
// Prover
// ════════════════════════════════════════════════════════════════════════

/**
 * Generates ZK integrity proofs that bind a claimed metric value to a
 * Merkle-committed receipt set.
 */
export class StatsProver {
    private readonly circuitsDir: string;
    private readonly proofRunner: ProofRunner;

    constructor(opts: StatsProverOptions) {
        this.circuitsDir = opts.circuitsDir;
        this.proofRunner = opts.proofRunner ?? defaultProofRunner;
    }

    /**
     * Prove `metric.value` is the honest aggregation of `receipts` against
     * `merkleRoot`. Per-receipt `merkleProofs` are zipped 1:1 with `receipts`.
     */
    public async proveStat(
        metric: MetricValue,
        receipts: ReceiptLike[],
        merkleProofs: MerkleProof[],
        merkleRoot: string,
    ): Promise<StatsHonestProof> {
        const def = METRICS[metric.id];
        if (!def) throw new Error(`unknown metric id: ${metric.id}`);
        if (!def.zk_provable) throw new NotProvableError(metric.id);

        if (receipts.length === 0) {
            throw new Error("proveStat: cannot prove over empty receipt set");
        }
        if (receipts.length > MAX_RECEIPTS_PER_PROOF) {
            throw new Error(
                `proveStat: receipts.length=${receipts.length} exceeds circuit cap ${MAX_RECEIPTS_PER_PROOF}`,
            );
        }
        if (receipts.length !== merkleProofs.length) {
            throw new Error(
                `proveStat: receipts.length=${receipts.length} != merkleProofs.length=${merkleProofs.length}`,
            );
        }

        const metricIdx = METRIC_ID_INDEX[metric.id];
        const witness = buildWitness({
            metric,
            metricIdx,
            receipts,
            merkleProofs,
            merkleRoot,
        });

        const { proof, publicSignals } = await this.proofRunner({
            circuit: "StatsHonestComputation",
            circuitsDir: this.circuitsDir,
            witness,
        });

        return {
            circuit: "StatsHonestComputation",
            public_inputs: publicSignals,
            proof,
            root: merkleRoot,
            metric,
        };
    }
}

/** Hard cap matching the StatsHonestComputation.circom template parameter. */
export const MAX_RECEIPTS_PER_PROOF = 64;

// ════════════════════════════════════════════════════════════════════════
// Witness construction
// ════════════════════════════════════════════════════════════════════════

function buildWitness(opts: {
    metric: MetricValue;
    metricIdx: number;
    receipts: ReceiptLike[];
    merkleProofs: MerkleProof[];
    merkleRoot: string;
}): Record<string, string | string[] | string[][]> {
    const { metric, metricIdx, receipts, merkleProofs, merkleRoot } = opts;

    // Fixed-arity tuple per receipt — the circuit consumes a 6-field row.
    // Layout: [status_bit, latency_ms, amount_usd_millis, tool_id, agent_id_hash, created_at].
    // We project receipts into integers here; the prover ships only integers
    // into snarkjs so the witness is fully deterministic.
    const entries: string[][] = receipts.map(receiptToFields);

    return {
        root: merkleRoot,
        metric_id: metricIdx.toString(),
        claimed_value: metric.value_fixed.toString(),
        n_records: metric.n_records_used.toString(),
        period_start: metric.period.start.toString(),
        period_end: metric.period.end.toString(),
        entries: entries as unknown as string[][],
        pathElements: merkleProofs.map((p) => p.pathElements) as unknown as string[][],
        pathIndices: merkleProofs.map((p) =>
            p.pathIndices.map((i) => i.toString()),
        ) as unknown as string[][],
    };
}

/** Project a receipt into the 6-field tuple the circuit expects. Pure
 *  function — exposed for the witness-equivalence test in
 *  `test/integrity-proof.test.ts`. */
export function receiptToFields(r: ReceiptLike): string[] {
    return [
        r.status === "ok" ? "1" : "0",
        (r.latency_ms ?? 0).toString(),
        Math.round((r.amount_usd ?? 0) * 1000).toString(), // milli-USD
        hashStringFieldElement(r.tool),
        hashStringFieldElement(r.agent_id),
        r.created_at.toString(),
    ];
}

/** Coerce a short string into a 64-bit field-element by SHA-256 + low-bits.
 *  Deterministic — same string → same integer across runs. The full Poseidon
 *  hash happens inside the circuit; this is just a witness-side projection. */
function hashStringFieldElement(s: string): string {
    if (!s) return "0";
    // Tiny xor-fold hash; deterministic and good enough for the witness — the
    // circuit re-hashes the field with Poseidon for the leaf commitment.
    let acc = 1469598103934665603n; // FNV-64 offset basis
    const prime = 1099511628211n;
    for (let i = 0; i < s.length; i++) {
        acc = (acc ^ BigInt(s.charCodeAt(i))) & 0xffffffffffffffffn;
        acc = (acc * prime) & 0xffffffffffffffffn;
    }
    return acc.toString();
}
