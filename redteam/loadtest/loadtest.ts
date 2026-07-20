/**
 * SauronID core load/soak driver.
 *
 * Setup: register N_USERS dev users, auth each, register one LLM agent per
 * user, upload one policy. Sustained: C workers loop a mixed workload for
 * DURATION_S seconds:
 *
 *   70%  signed POST /agent/egress/log   (full call-sig v2 verification:
 *        Ed25519 verify + single-use nonce consume + agent lookup + insert)
 *   20%  GET  /healthz                    (unauthenticated liveness)
 *   10%  POST /v1/policy/evaluate         (admin-gated policy DSL, simulator mode)
 *
 * Output: JSON results file + console summary. RSS of the core process
 * (/proc/$CORE_PID/status VmRSS) and SQLite file size sampled every 10s.
 *
 * Run via run.sh — it boots core on :3021 with a fresh DB and sets the env.
 */

import * as fs from "fs";
import * as path from "path";

import { SauronIDClient, registerLlmAgent, SignedAgent } from "@sauronid/agentic";

const CORE_URL = process.env.CORE_URL ?? "http://localhost:3021";
const ADMIN_KEY = process.env.SAURON_ADMIN_KEY ?? "";
const N_USERS = intEnv("N_USERS", 4);
const C = intEnv("C", 4);
const DURATION_S = intEnv("DURATION_S", 60);
const CORE_PID = process.env.CORE_PID ?? "";
const DB_PATH = process.env.DATABASE_PATH ?? "";
const RESULTS_FILE =
    process.env.RESULTS_FILE ?? path.join("results", `run-${Date.now()}.json`);

if (!ADMIN_KEY) {
    console.error("SAURON_ADMIN_KEY not set (source scripts/lib/dev_secrets.sh)");
    process.exit(1);
}

function intEnv(name: string, def: number): number {
    const v = parseInt(process.env[name] ?? "", 10);
    return Number.isFinite(v) && v > 0 ? v : def;
}

// ---------------------------------------------------------------------------
// Per-op sample stores. Plain number arrays: ~1.5M samples in a 15-min run
// is fine in memory; raw latencies are NOT written to the JSON, only stats.
// ---------------------------------------------------------------------------

type OpName = "signed_egress_log" | "healthz" | "policy_evaluate";

interface OpStore {
    ms: number[];
    minute: number[]; // relative minute of each sample, for drift buckets
    statuses: Map<number, number>; // HTTP status (0 = transport error) -> count
    errorSamples: string[]; // first few unique error bodies/messages
}

const ops: Record<OpName, OpStore> = {
    signed_egress_log: newStore(),
    healthz: newStore(),
    policy_evaluate: newStore(),
};

function newStore(): OpStore {
    return { ms: [], minute: [], statuses: new Map(), errorSamples: [] };
}

function record(op: OpName, ms: number, status: number, minute: number, errBody?: string) {
    const s = ops[op];
    s.ms.push(ms);
    s.minute.push(minute);
    s.statuses.set(status, (s.statuses.get(status) ?? 0) + 1);
    if (status !== 200 && errBody && s.errorSamples.length < 5) {
        const line = `${status}: ${errBody.slice(0, 200)}`;
        if (!s.errorSamples.includes(line)) s.errorSamples.push(line);
    }
}

function percentile(sorted: number[], p: number): number {
    if (sorted.length === 0) return 0;
    const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[Math.max(0, idx)];
}

function opSummary(name: OpName, wallS: number) {
    const s = ops[name];
    const sorted = [...s.ms].sort((a, b) => a - b);
    const r = (x: number) => Math.round(x * 100) / 100;
    const statuses: Record<string, number> = {};
    for (const [k, v] of s.statuses) statuses[String(k)] = v;
    const errors = [...s.statuses.entries()]
        .filter(([st]) => st !== 200)
        .reduce((a, [, n]) => a + n, 0);
    return {
        count: s.ms.length,
        rps: r(s.ms.length / wallS),
        p50_ms: r(percentile(sorted, 50)),
        p90_ms: r(percentile(sorted, 90)),
        p99_ms: r(percentile(sorted, 99)),
        max_ms: r(percentile(sorted, 100)),
        errors,
        statuses,
        error_samples: s.errorSamples,
    };
}

/** Overall p50/p99 per relative minute — makes latency drift visible. */
function perMinuteDrift(): Array<{ minute: number; count: number; p50_ms: number; p99_ms: number }> {
    const buckets = new Map<number, number[]>();
    for (const name of Object.keys(ops) as OpName[]) {
        const s = ops[name];
        for (let i = 0; i < s.ms.length; i++) {
            let arr = buckets.get(s.minute[i]);
            if (!arr) buckets.set(s.minute[i], (arr = []));
            arr.push(s.ms[i]);
        }
    }
    const r = (x: number) => Math.round(x * 100) / 100;
    return [...buckets.entries()]
        .sort(([a], [b]) => a - b)
        .map(([minute, arr]) => {
            arr.sort((a, b) => a - b);
            return {
                minute,
                count: arr.length,
                p50_ms: r(percentile(arr, 50)),
                p99_ms: r(percentile(arr, 99)),
            };
        });
}

// ---------------------------------------------------------------------------
// RSS + DB-size sampler
// ---------------------------------------------------------------------------

interface RssSample {
    t_s: number;
    rss_mb: number | null;
    db_mb: number | null;
}

function sampleRss(t0: number): RssSample {
    let rssMb: number | null = null;
    let dbMb: number | null = null;
    if (CORE_PID) {
        try {
            const status = fs.readFileSync(`/proc/${CORE_PID}/status`, "utf8");
            const m = status.match(/VmRSS:\s+(\d+)\s+kB/);
            if (m) rssMb = Math.round((parseInt(m[1], 10) / 1024) * 10) / 10;
        } catch {
            /* process gone */
        }
    }
    if (DB_PATH) {
        try {
            // main file + WAL (WAL holds the not-yet-checkpointed churn)
            let bytes = fs.statSync(DB_PATH).size;
            try {
                bytes += fs.statSync(`${DB_PATH}-wal`).size;
            } catch {
                /* no wal */
            }
            dbMb = Math.round((bytes / 1024 / 1024) * 100) / 100;
        } catch {
            /* no db file */
        }
    }
    return { t_s: Math.round((Date.now() - t0) / 1000), rss_mb: rssMb, db_mb: dbMb };
}

// ---------------------------------------------------------------------------
// Workload ops
// ---------------------------------------------------------------------------

async function timedFetch(
    client: SauronIDClient,
    op: OpName,
    minute: number,
    fn: () => Promise<Response>
): Promise<void> {
    const t0 = process.hrtime.bigint();
    let status = 0;
    let errBody: string | undefined;
    try {
        const resp = await fn();
        status = resp.status;
        // Always drain the body so sockets are reusable.
        const text = await resp.text();
        if (status !== 200) errBody = text;
    } catch (e) {
        status = 0;
        errBody = e instanceof Error ? e.message : String(e);
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    record(op, ms, status, minute, errBody);
}

async function main(): Promise<void> {
    const client = new SauronIDClient({ baseUrl: CORE_URL, adminKey: ADMIN_KEY });

    // ----- setup phase ------------------------------------------------------
    console.log(`[setup] core=${CORE_URL} users=${N_USERS} workers=${C} duration=${DURATION_S}s`);
    const runTag = Date.now().toString(36);
    const agents: SignedAgent[] = [];
    for (let i = 0; i < N_USERS; i++) {
        const email = `loadtest-${runTag}-${i}@sauron.dev`;
        const password = `pass_load_${i}`;
        await client.postJson("/dev/register_user", {
            site_name: "Monzo",
            email,
            password,
            first_name: "Load",
            last_name: `Test${i}`,
            date_of_birth: "1990-01-01",
            nationality: "FR",
        });
        const auth = await client.userAuth(email, password);
        const agent = await registerLlmAgent(client, {
            userSession: auth.session,
            userKeyImage: auth.key_image,
            modelId: "claude-sonnet-4-5",
            systemPrompt: "Load-test agent.",
            tools: ["search"],
            ttlSecs: DURATION_S + 3600, // must outlive the run
        });
        agents.push(agent);
    }
    console.log(`[setup] ${agents.length} users+agents registered`);

    const { policy_id } = await client.postJson(
        "/v1/policy/upload",
        {
            raw_yaml:
                'version: "1"\nagent: loadtest_agent\nbinding:\n  allowed_tools: [search]\n  max_budget_usd: 100\n',
        },
        client.adminHeaders()
    );
    console.log(`[setup] policy uploaded: ${policy_id}`);

    let evalSeq = 0;
    function egressBody(agent: SignedAgent) {
        return {
            agent_id: agent.agentId,
            target_host: "api.example.com",
            target_path: "/v1/load",
            method: "GET",
            body_hash_hex: "",
            status_code: 200,
        };
    }
    function evaluateBody(policyId: string) {
        // No agent_id => simulator mode: pure policy-engine evaluation, no
        // spend-ledger lookup. Cheap and deterministic.
        return {
            policy_id: policyId,
            action: {
                action_id: `load-${runTag}-${evalSeq++}`,
                tool: "search",
                timestamp: Math.floor(Date.now() / 1000),
            },
        };
    }

    // Sanity: one of each op must return 200 before we start the clock.
    const warm = await agents[0].call("POST", "/agent/egress/log", {
        jsonBody: egressBody(agents[0]),
    });
    if (warm.status !== 200) {
        throw new Error(`warm-up signed call failed: ${warm.status} ${await warm.text()}`);
    }
    await warm.text().catch(() => {});
    const warmPol = await client.postJson("/v1/policy/evaluate", evaluateBody(policy_id), {
        ...client.adminHeaders(),
        "content-type": "application/json",
    });
    if (!warmPol.verdict) throw new Error("warm-up policy evaluate returned no verdict");
    console.log(`[setup] warm-up ok (signed=200, policy verdict=${JSON.stringify(warmPol.verdict)})`);

    // ----- sustained phase ---------------------------------------------------
    const t0 = Date.now();
    const deadline = t0 + DURATION_S * 1000;
    const rssSamples: RssSample[] = [sampleRss(t0)];
    const rssTimer = setInterval(() => {
        const s = sampleRss(t0);
        rssSamples.push(s);
        const total = Object.values(ops).reduce((a, o) => a + o.ms.length, 0);
        console.log(
            `[t+${s.t_s}s] reqs=${total} rss=${s.rss_mb ?? "?"}MB db=${s.db_mb ?? "?"}MB`
        );
    }, 10_000);

    async function worker(id: number): Promise<void> {
        const agent = agents[id % agents.length];
        while (Date.now() < deadline) {
            const minute = Math.floor((Date.now() - t0) / 60_000);
            const r = Math.random();
            if (r < 0.7) {
                await timedFetch(client, "signed_egress_log", minute, () =>
                    agent.call("POST", "/agent/egress/log", { jsonBody: egressBody(agent) })
                );
            } else if (r < 0.9) {
                await timedFetch(client, "healthz", minute, () =>
                    client.fetchRaw("GET", "/healthz")
                );
            } else {
                await timedFetch(client, "policy_evaluate", minute, () =>
                    client.fetchRaw("POST", "/v1/policy/evaluate", {
                        body: JSON.stringify(evaluateBody(policy_id)),
                        headers: {
                            "content-type": "application/json",
                            ...client.adminHeaders(),
                        },
                    })
                );
            }
        }
    }

    console.log(`[run] ${C} workers for ${DURATION_S}s ...`);
    await Promise.all(Array.from({ length: C }, (_, i) => worker(i)));
    clearInterval(rssTimer);
    rssSamples.push(sampleRss(t0));
    const wallS = (Date.now() - t0) / 1000;

    // ----- report ------------------------------------------------------------
    const summary = {
        config: {
            core_url: CORE_URL,
            n_users: N_USERS,
            concurrency: C,
            duration_s: DURATION_S,
            wall_s: Math.round(wallS * 10) / 10,
            core_pid: CORE_PID || null,
            db_path: DB_PATH || null,
            started_at: new Date(t0).toISOString(),
            mix: { signed_egress_log: 0.7, healthz: 0.2, policy_evaluate: 0.1 },
        },
        ops: {
            signed_egress_log: opSummary("signed_egress_log", wallS),
            healthz: opSummary("healthz", wallS),
            policy_evaluate: opSummary("policy_evaluate", wallS),
        },
        overall: {
            count: Object.values(ops).reduce((a, o) => a + o.ms.length, 0),
            rps:
                Math.round(
                    (Object.values(ops).reduce((a, o) => a + o.ms.length, 0) / wallS) * 100
                ) / 100,
            errors: (Object.keys(ops) as OpName[])
                .map((n) => opSummary(n, wallS).errors)
                .reduce((a, b) => a + b, 0),
        },
        rss_samples: rssSamples,
        per_minute_drift: perMinuteDrift(),
    };

    fs.mkdirSync(path.dirname(RESULTS_FILE), { recursive: true });
    fs.writeFileSync(RESULTS_FILE, JSON.stringify(summary, null, 2));

    console.log("\n=== load test summary ===");
    console.log(
        `total ${summary.overall.count} reqs in ${summary.config.wall_s}s -> ${summary.overall.rps} rps, ${summary.overall.errors} errors`
    );
    for (const name of Object.keys(ops) as OpName[]) {
        const o = summary.ops[name];
        console.log(
            `${name.padEnd(18)} n=${String(o.count).padEnd(8)} rps=${String(o.rps).padEnd(8)} ` +
                `p50=${o.p50_ms}ms p90=${o.p90_ms}ms p99=${o.p99_ms}ms max=${o.max_ms}ms ` +
                `errors=${o.errors} statuses=${JSON.stringify(o.statuses)}`
        );
        for (const e of o.error_samples) console.log(`  sample error -> ${e}`);
    }
    const first = rssSamples.find((s) => s.rss_mb != null);
    const last = [...rssSamples].reverse().find((s) => s.rss_mb != null);
    if (first && last) {
        console.log(`core RSS ${first.rss_mb}MB -> ${last.rss_mb}MB; db ${first.db_mb}MB -> ${last.db_mb}MB`);
    }
    console.log(`results written: ${RESULTS_FILE}`);

    // Fail loudly if the run was mostly errors — a green exit on a broken run
    // is how load-test lies get told.
    if (summary.overall.count === 0 || summary.overall.errors > summary.overall.count / 2) {
        console.error("FAIL: majority of requests errored");
        process.exit(2);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
