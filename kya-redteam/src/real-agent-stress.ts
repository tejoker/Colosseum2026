/**
 * Tavily + Stripe test-mode stress harness for agent payment flows.
 *
 * This runner is intentionally cost guarded:
 * - Stripe live keys are rejected. Only sk_test_* is accepted.
 * - Stripe PaymentIntents use manual capture and are canceled, never captured.
 * - Tavily calls are capped; without TAVILY_API_KEY the runner uses a local dry run.
 */

import { createHash, generateKeyPairSync, KeyObject, sign as cryptoSign } from "crypto";
import { CoreApi, randSuffix } from "./core-api";

type JsonRecord = Record<string, unknown>;

interface TavilyContext {
    mode: "tavily" | "dry_run";
    query: string;
    answer: string;
    topUrl?: string;
    contextHash: string;
}

interface StripeAuthorization {
    mode: "stripe_test" | "dry_run";
    id: string;
    status: string;
}

interface RunResult {
    index: number;
    ok: boolean;
    ms: number;
    mode: {
        tavily: TavilyContext["mode"];
        stripe: StripeAuthorization["mode"];
    };
    stripeStatus?: string;
    error?: string;
}

const baseUrl = process.env.API_URL || process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";
const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";

const allowHighLimits = process.env.REAL_AGENT_STRESS_HIGH_LIMITS === "1";
const iterations = readBoundedInt("REAL_AGENT_STRESS_ITERATIONS", 3, 1, allowHighLimits ? 250 : 25);
const concurrency = readBoundedInt("REAL_AGENT_STRESS_CONCURRENCY", 2, 1, allowHighLimits ? 25 : 4);
const amountMinor = readBoundedInt("REAL_AGENT_STRESS_AMOUNT_MINOR", 1234, 50, 5000);
const tavilyMaxCalls = readBoundedInt("REAL_AGENT_TAVILY_MAX_CALLS", Math.min(iterations, 3), 0, allowHighLimits ? 100 : 10);
const tavilyMaxResults = readBoundedInt("REAL_AGENT_TAVILY_MAX_RESULTS", 3, 1, 5);
const runNegativeChecks = process.env.REAL_AGENT_NEGATIVE_CHECKS !== "0";

const tavilyApiKey = process.env.TAVILY_API_KEY;
const tavilyEndpoint = process.env.TAVILY_API_URL || "https://api.tavily.com/search";
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const stripeEndpoint = process.env.STRIPE_API_URL || "https://api.stripe.com";

let tavilyCallsUsed = 0;

function readBoundedInt(name: string, fallback: number, min: number, max: number): number {
    const raw = process.env[name];
    const parsed = raw ? Number.parseInt(raw, 10) : fallback;
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function sha256Hex(value: string): string {
    return createHash("sha256").update(value).digest("hex");
}

function firstString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value : undefined;
}

function safeSnippet(value: string, max = 220): string {
    return value.replace(/\s+/g, " ").trim().slice(0, max);
}

function createPopKeyPair(): { publicKeyB64u: string; privateKey: KeyObject } {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const x = firstString((publicJwk as { x?: unknown }).x);
    if (!x) throw new Error("failed to export Ed25519 public JWK x");
    return { publicKeyB64u: x, privateKey };
}

function signPopJws(challenge: string, privateKey: KeyObject): string {
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(challenge, "utf8").toString("base64url");
    const signingInput = `${header}.${payload}`;
    const signature = cryptoSign(null, Buffer.from(signingInput), privateKey).toString("base64url");
    return `${signingInput}.${signature}`;
}

async function tavilySearch(query: string): Promise<TavilyContext> {
    if (!tavilyApiKey || tavilyCallsUsed >= tavilyMaxCalls) {
        const answer = `dry-run Tavily context for: ${query}`;
        return {
            mode: "dry_run",
            query,
            answer,
            contextHash: sha256Hex(answer),
        };
    }

    tavilyCallsUsed++;
    const response = await fetch(tavilyEndpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tavilyApiKey}`,
        },
        body: JSON.stringify({
            query,
            search_depth: "basic",
            include_answer: true,
            include_raw_content: false,
            max_results: tavilyMaxResults,
        }),
    });
    const raw = await response.text();
    if (!response.ok) {
        throw new Error(`Tavily ${response.status}: ${safeSnippet(raw)}`);
    }

    const body = JSON.parse(raw) as {
        answer?: unknown;
        results?: { url?: unknown; title?: unknown; content?: unknown }[];
    };
    const top = body.results?.[0];
    const answer = [
        firstString(body.answer),
        firstString(top?.title),
        firstString(top?.content),
        firstString(top?.url),
    ]
        .filter(Boolean)
        .join(" | ");

    return {
        mode: "tavily",
        query,
        answer: safeSnippet(answer || raw),
        topUrl: firstString(top?.url),
        contextHash: sha256Hex(raw),
    };
}

function assertStripeKeyIsSafe(): void {
    if (!stripeSecretKey) return;
    if (stripeSecretKey.startsWith("sk_live_")) {
        throw new Error("Refusing to run with a live Stripe key. Use a sk_test_* key for this harness.");
    }
    if (!stripeSecretKey.startsWith("sk_test_")) {
        throw new Error("STRIPE_SECRET_KEY must be a Stripe test secret key starting with sk_test_");
    }
}

async function stripeAuthorizeManualCapture(input: {
    amountMinor: number;
    currency: string;
    paymentRef: string;
    authorizationId: string;
    agentId: string;
    merchantId: string;
}): Promise<StripeAuthorization> {
    if (!stripeSecretKey) {
        return {
            mode: "dry_run",
            id: `pi_dry_${sha256Hex(input.paymentRef).slice(0, 18)}`,
            status: "requires_capture",
        };
    }

    const params = new URLSearchParams();
    params.set("amount", String(input.amountMinor));
    params.set("currency", input.currency.toLowerCase());
    params.set("confirm", "true");
    params.set("capture_method", "manual");
    params.set("payment_method", "pm_card_visa");
    params.append("payment_method_types[]", "card");
    params.set("description", "SauronID real-agent stress test authorization");
    params.set("metadata[sauron_authorization_id]", input.authorizationId);
    params.set("metadata[sauron_payment_ref]", input.paymentRef);
    params.set("metadata[sauron_agent_id]", input.agentId);
    params.set("metadata[sauron_merchant_id]", input.merchantId);

    const response = await fetch(`${stripeEndpoint}/v1/payment_intents`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${stripeSecretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": `sauron-stress-${input.paymentRef}`,
        },
        body: params,
    });
    const raw = await response.text();
    if (!response.ok) {
        throw new Error(`Stripe create PaymentIntent ${response.status}: ${safeSnippet(raw)}`);
    }
    const body = JSON.parse(raw) as { id?: unknown; status?: unknown };
    const id = firstString(body.id);
    const status = firstString(body.status);
    if (!id || !status) throw new Error(`Stripe PaymentIntent response missing id/status: ${safeSnippet(raw)}`);
    if (status !== "requires_capture") {
        throw new Error(`Stripe PaymentIntent expected requires_capture, got ${status}`);
    }
    return { mode: "stripe_test", id, status };
}

async function stripeCancelAuthorization(paymentIntentId: string): Promise<void> {
    if (!stripeSecretKey || paymentIntentId.startsWith("pi_dry_")) return;
    const response = await fetch(`${stripeEndpoint}/v1/payment_intents/${paymentIntentId}/cancel`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${stripeSecretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });
    const raw = await response.text();
    if (!response.ok) {
        throw new Error(`Stripe cancel PaymentIntent ${response.status}: ${safeSnippet(raw)}`);
    }
}

async function authorizeWithFreshPop(input: {
    api: CoreApi;
    session: string;
    agentId: string;
    ajwt: string;
    privateKey: KeyObject;
    amountMinor: number;
    currency: string;
    merchantId: string;
    paymentRef: string;
}): Promise<{ status: number; data: JsonRecord; raw: string }> {
    const challenge = await input.api.agentPopChallenge(input.session, input.agentId);
    return input.api.agentPaymentAuthorize({
        ajwt: input.ajwt,
        amount_minor: input.amountMinor,
        currency: input.currency,
        merchant_id: input.merchantId,
        payment_ref: input.paymentRef,
        pop_challenge_id: challenge.pop_challenge_id,
        pop_jws: signPopJws(challenge.challenge, input.privateKey),
    });
}

async function runOne(api: CoreApi, index: number): Promise<RunResult> {
    const started = process.hrtime.bigint();
    try {
        const sfx = `${index}-${randSuffix()}`;
        const query = [
            "AI agent payment authorization merchant allowlist risk controls",
            "Stripe test mode PaymentIntent manual capture cancel no real money",
            "agentic commerce bounded payment authorization web search tool",
            "autonomous agents payment fraud policy proof of possession",
        ][index % 4];
        const tavily = await tavilySearch(query);
        const merchantId = `mrc_agent_${tavily.contextHash.slice(0, 12)}_${sfx}`;
        const email = `real_agent_${sfx}@sauron.local`;
        const password = `Passw0rd!${sfx}`;
        const paymentRef = `stress_${sfx}`;
        const currency = "EUR";
        const { publicKeyB64u, privateKey } = createPopKeyPair();

        await api.ensureClient(bankSite, "BANK");
        const { public_key_hex } = await api.devRegisterUser({
            site_name: bankSite,
            email,
            password,
            first_name: "Real",
            last_name: "Agent",
            date_of_birth: "1990-01-01",
            nationality: "FRA",
        });
        const { session, key_image } = await api.userAuth(email, password);
        const intent = {
            action: "payment_initiation",
            scope: ["payment_initiation"],
            maxAmount: amountMinor / 100,
            currency,
            constraints: {
                merchant_allowlist: [merchantId],
                tavily_context_hash: tavily.contextHash,
                tavily_top_url: tavily.topUrl ?? "dry-run",
            },
        };

        const reg = await api.agentRegister(session, {
            human_key_image: key_image,
            agent_checksum: `sha256:${sha256Hex(`${tavily.contextHash}:${sfx}`)}`,
            intent_json: JSON.stringify(intent),
            public_key_hex: public_key_hex.toLowerCase(),
            ttl_secs: 3600,
            pop_public_key_b64u: publicKeyB64u,
        });
        if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
        const ajwt = firstString(reg.data.ajwt);
        const agentId = firstString(reg.data.agent_id);
        if (!ajwt || !agentId) throw new Error(`agent/register missing ajwt/agent_id: ${reg.raw}`);

        if (runNegativeChecks) {
            const denied = await authorizeWithFreshPop({
                api,
                session,
                agentId,
                ajwt,
                privateKey,
                amountMinor: amountMinor + 1,
                currency,
                merchantId,
                paymentRef: `${paymentRef}_over_limit`,
            });
            if (denied.status === 200) {
                throw new Error(`over-limit authorization unexpectedly succeeded: ${denied.raw}`);
            }
        }

        const authorized = await authorizeWithFreshPop({
            api,
            session,
            agentId,
            ajwt,
            privateKey,
            amountMinor,
            currency,
            merchantId,
            paymentRef,
        });
        if (authorized.status !== 200) {
            throw new Error(`agent/payment/authorize ${authorized.status}: ${authorized.raw}`);
        }
        const authorizationId = firstString(authorized.data.authorization_id);
        if (!authorizationId) throw new Error(`payment authorization missing authorization_id: ${authorized.raw}`);

        const stripe = await stripeAuthorizeManualCapture({
            amountMinor,
            currency,
            paymentRef,
            authorizationId,
            agentId,
            merchantId,
        });
        try {
            const consumed = await api.merchantPaymentConsume(authorizationId, merchantId);
            if (consumed.status !== 200) {
                throw new Error(`merchant/payment/consume ${consumed.status}: ${consumed.raw}`);
            }
        } finally {
            await stripeCancelAuthorization(stripe.id);
        }

        return {
            index,
            ok: true,
            ms: elapsedMs(started),
            mode: { tavily: tavily.mode, stripe: stripe.mode },
            stripeStatus: stripe.status,
        };
    } catch (error) {
        return {
            index,
            ok: false,
            ms: elapsedMs(started),
            mode: {
                tavily: tavilyApiKey ? "tavily" : "dry_run",
                stripe: stripeSecretKey ? "stripe_test" : "dry_run",
            },
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

function elapsedMs(started: bigint): number {
    return Number((process.hrtime.bigint() - started) / 1_000_000n);
}

async function runPool(api: CoreApi): Promise<RunResult[]> {
    const results: RunResult[] = [];
    let next = 0;
    const workers = Array.from({ length: Math.min(concurrency, iterations) }, async () => {
        while (next < iterations) {
            const index = next++;
            process.stdout.write(`[real-agent-stress] run ${index + 1}/${iterations} ... `);
            const result = await runOne(api, index);
            results.push(result);
            console.log(result.ok ? `OK ${result.ms}ms` : `FAIL ${result.ms}ms`);
            if (result.error) console.error(`  ${result.error}`);
        }
    });
    await Promise.all(workers);
    return results.sort((a, b) => a.index - b.index);
}

async function main(): Promise<void> {
    assertStripeKeyIsSafe();
    console.log(`\nReal-agent stress: ${baseUrl}`);
    console.log(
        `iterations=${iterations} concurrency=${concurrency} tavily_calls_cap=${tavilyMaxCalls} stripe=${
            stripeSecretKey ? "test" : "dry-run"
        } negative_checks=${runNegativeChecks ? "on" : "off"}`
    );

    const api = new CoreApi({ baseUrl, adminKey });
    const results = await runPool(api);
    const failed = results.filter((r) => !r.ok);
    const ok = results.length - failed.length;
    const avgMs = results.length
        ? Math.round(results.reduce((sum, r) => sum + r.ms, 0) / results.length)
        : 0;

    console.log(`\nReal-agent stress summary: ok=${ok} failed=${failed.length} avg_ms=${avgMs}`);
    console.log(`Tavily calls used: ${tavilyCallsUsed}/${tavilyMaxCalls}`);
    if (failed.length > 0) {
        process.exit(1);
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
