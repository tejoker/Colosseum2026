/**
 * Sprint 7 — WeeklyStatsScheduler tests.
 *
 * Mocked fetch + mocked StatsProver. Asserts:
 *   1. runOnce submits every provable metric and skips the others
 *   2. zero receipts → all skipped
 *   3. server 4xx → onError fires per failing metric
 *   4. createWeeklyScheduler returns an instance with start/stop API
 *   5. submitWeeklyStats one-shot helper drives the same flow
 */

import {
    WeeklyStatsScheduler,
    createWeeklyScheduler,
    submitWeeklyStats,
    type WeeklyStatsSchedulerOptions,
    type SubmitResponse,
} from "../src/scheduler";
import {
    StatsProver,
    type ProofRunner,
} from "../src/stats/integrity-proof";
import type { ReceiptLike } from "../src/stats/local-aggregate";
import { METRICS } from "../src/stats/metric-catalog";

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

function stubProofRunner(): ProofRunner {
    return async ({ witness }) => ({
        proof: stubProof,
        publicSignals: [
            "1",
            witness.root as string,
            witness.metric_id as string,
            witness.claimed_value as string,
            witness.n_records as string,
            witness.period_start as string,
            witness.period_end as string,
        ],
    });
}

function mkReceipts(): ReceiptLike[] {
    return [
        {
            receipt_id: "r1",
            action_hash: "h1",
            agent_id: "A",
            status: "ok",
            tool: "echo",
            created_at: 100,
            latency_ms: 50,
            amount_usd: 1.0,
        },
        {
            receipt_id: "r2",
            action_hash: "h2",
            agent_id: "B",
            status: "denied",
            tool: "shell",
            created_at: 200,
            latency_ms: 80,
            amount_usd: 0.0,
        },
        {
            receipt_id: "r3",
            action_hash: "h3",
            agent_id: "A",
            status: "ok",
            tool: "echo",
            created_at: 300,
            latency_ms: 75,
            amount_usd: 0.5,
        },
        {
            receipt_id: "r4",
            action_hash: "h4",
            agent_id: "C",
            status: "ok",
            tool: "echo",
            created_at: 400,
            latency_ms: 90,
            amount_usd: 2.0,
        },
    ];
}

function mockFetchFactory(
    responses: Array<{ status: number; body: SubmitResponse | { error: string } }>,
): { fetch: typeof fetch; calls: Array<{ url: string; body: string }> } {
    const calls: Array<{ url: string; body: string }> = [];
    let i = 0;
    const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
        calls.push({
            url: typeof input === "string" ? input : input.toString(),
            body: typeof init?.body === "string" ? init!.body : "",
        });
        const r = responses[Math.min(i, responses.length - 1)];
        i++;
        return new Response(JSON.stringify(r.body), {
            status: r.status,
            headers: { "content-type": "application/json" },
        });
    }) as unknown as typeof fetch;
    return { fetch: f, calls };
}

function buildOpts(over: Partial<WeeklyStatsSchedulerOptions> = {}): WeeklyStatsSchedulerOptions {
    const receipts = mkReceipts();
    const prover = new StatsProver({
        circuitsDir: "/unused",
        proofRunner: stubProofRunner(),
    });
    return {
        coreUrl: "http://core",
        adminKey: "dev",
        circuitsDir: "/unused",
        prover,
        periodProvider: () => ({ start: 0, end: 1000 }),
        receiptsProvider: async () => receipts,
        merkleProofProvider: async (rs) => ({
            root: "deadbeef",
            checkpointId: "zkc_test",
            proofs: rs.map(() => ({ pathElements: ["0", "0"], pathIndices: [0, 0] })),
        }),
        ...over,
    };
}

async function testHappyPath() {
    console.log("\n═══ runOnce: provable metrics submitted, others skipped ═══");
    const { fetch: f, calls } = mockFetchFactory([
        {
            status: 200,
            body: { stored: true, latency_ms_verify: 10, statement_hash: "ah" },
        },
    ]);
    const onSubmit: string[] = [];
    const onSkip: string[] = [];
    const sched = new WeeklyStatsScheduler(
        buildOpts({
            httpFetch: f,
            onSubmit: (id) => onSubmit.push(id),
            onSkip: (id) => onSkip.push(id),
        }),
    );
    const outcome = await sched.runOnce();

    const provable = Object.values(METRICS).filter((d) => d.zk_provable).length;
    const total = Object.keys(METRICS).length;
    const submitted = onSubmit.length;
    const skipped = onSkip.length;

    assert(submitted === provable, `submitted = provable count (${submitted}/${provable})`);
    assert(
        skipped === total - provable,
        `skipped = non-provable count (${skipped}/${total - provable})`,
    );
    assert(calls.length === provable, `fetch called once per provable metric (got ${calls.length})`);
    assert(
        calls.every((c) => c.url === "http://core/v1/stats/submit"),
        "every call hits /v1/stats/submit",
    );
    const firstBody = JSON.parse(calls[0].body);
    assert(firstBody.tenant_id === "default", "tenant_id default");
    assert(firstBody.merkle_root === "deadbeef", "merkle_root forwarded");
    assert(typeof firstBody.claimed_value === "number", "claimed_value is fixed-point number");
    assert(
        Object.values(outcome).filter((v) => v === "submitted").length === provable,
        "outcome map counts match",
    );
}

async function testEmptyReceiptsAllSkipped() {
    console.log("\n═══ runOnce: empty receipts → all skipped ═══");
    const { fetch: f, calls } = mockFetchFactory([
        {
            status: 200,
            body: { stored: true, latency_ms_verify: 1, statement_hash: "" },
        },
    ]);
    const skipped: string[] = [];
    const sched = new WeeklyStatsScheduler(
        buildOpts({
            httpFetch: f,
            receiptsProvider: async () => [],
            onSkip: (id) => skipped.push(id),
        }),
    );
    const outcome = await sched.runOnce();
    const total = Object.keys(METRICS).length;
    assert(skipped.length === total, `every metric skipped (${skipped.length}/${total})`);
    assert(calls.length === 0, "no fetch calls fired");
    assert(
        Object.values(outcome).every((v) => v === "skipped"),
        "outcome map all skipped",
    );
}

async function testServerErrorFiresOnError() {
    console.log("\n═══ runOnce: server 4xx fires onError per metric ═══");
    const { fetch: f } = mockFetchFactory([
        { status: 400, body: { error: "bad" } },
    ]);
    const errors: Array<{ id: string; msg: string }> = [];
    const sched = new WeeklyStatsScheduler(
        buildOpts({
            httpFetch: f,
            onError: (id, e) => errors.push({ id, msg: e.message }),
        }),
    );
    const outcome = await sched.runOnce();
    const provable = Object.values(METRICS).filter((d) => d.zk_provable).length;
    assert(errors.length === provable, `onError fired for each provable metric (${errors.length}/${provable})`);
    assert(
        errors.every((e) => /400/.test(e.msg)),
        "errors carry the upstream status code",
    );
    assert(
        Object.values(outcome).filter((v) => v === "error").length === provable,
        "outcome map error count matches",
    );
}

async function testFactoryAndOneShot() {
    console.log("\n═══ factory + one-shot helpers ═══");
    const { fetch: f } = mockFetchFactory([
        {
            status: 200,
            body: { stored: true, latency_ms_verify: 5, statement_hash: "x" },
        },
    ]);
    const sched = createWeeklyScheduler(buildOpts({ httpFetch: f }));
    assert(sched instanceof WeeklyStatsScheduler, "createWeeklyScheduler returns instance");
    // start/stop are idempotent + side-effect-free in tests when intervalMs is huge.
    sched.start();
    sched.start(); // no throw on second
    sched.stop();
    sched.stop(); // no throw on second

    // One-shot helper drives the same flow.
    const outcome = await submitWeeklyStats(buildOpts({ httpFetch: f }));
    const provable = Object.values(METRICS).filter((d) => d.zk_provable).length;
    assert(
        Object.values(outcome).filter((v) => v === "submitted").length === provable,
        "submitWeeklyStats submits provable subset",
    );
}

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  SauronID — Sprint 7 WeeklyStatsScheduler tests ║");
    console.log("╚══════════════════════════════════════════════════╝");
    try {
        await testHappyPath();
        await testEmptyReceiptsAllSkipped();
        await testServerErrorFiresOnError();
        await testFactoryAndOneShot();

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
