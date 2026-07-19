/**
 * Vercel AI SDK tools guarded by a SauronID policy (illustrative).
 *
 * sauronTools() wraps the tool set you pass to generateText/streamText so
 * every execute() is policy-checked first. A denied tool resolves to a
 * "Policy denied: ..." string result, so the model recovers mid-generation.
 *
 * Prereqs: `docker compose up` at the repo root, `npm install` here.
 */

import { tool } from "ai";
import { z } from "zod";

import { SauronIDClient, createEnforcer, sauronTools } from "@sauronid/agentic";

const CORE_URL = "http://localhost:3001";
const DEV_ADMIN_KEY = "dev-only-admin-key-not-for-production";

const POLICY = `version: "1"
agent: example_vercel_ai
binding:
  allowed_tools: [search]
  max_budget_usd: 25
`;

async function main(): Promise<void> {
    const client = new SauronIDClient({ baseUrl: CORE_URL, adminKey: DEV_ADMIN_KEY });
    const { policy_id } = await client.postJson(
        "/v1/policy/upload",
        { raw_yaml: POLICY },
        client.adminHeaders()
    );
    console.log(`policy uploaded: ${policy_id}`);

    const enf = await createEnforcer({
        coreUrl: CORE_URL,
        adminKey: DEV_ADMIN_KEY,
        policyId: policy_id,
        agentId: "example-vercel-ai",
    });

    const tools = sauronTools(
        {
            search: tool({
                description: "Search the product catalog.",
                inputSchema: z.object({ query: z.string() }),
                execute: async ({ query }) => `3 hits for '${query}'`,
            }),
            send_payment: tool({
                description: "Send a payment. Not on the policy allowlist.",
                inputSchema: z.object({ amount_usd: z.number(), to: z.string() }),
                execute: async ({ amount_usd, to }) => `sent $${amount_usd} to ${to}`,
            }),
        },
        { enforcer: enf }
    );

    // In a real app, hand `tools` to generateText/streamText:
    //   await generateText({ model: yourModel, tools, prompt: "..." });
    // Here we invoke execute() directly so the example runs without an LLM key.
    const opts = { toolCallId: "t", messages: [] };
    console.log("search ->", await tools.search.execute?.({ query: "blue widgets" }, opts));
    console.log(
        "send_payment ->",
        await tools.send_payment.execute?.({ amount_usd: 9.5, to: "acme" }, opts)
    );

    await enf.stop();
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
