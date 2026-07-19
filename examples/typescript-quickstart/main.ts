/**
 * SauronID TypeScript quickstart: register, make a signed call, get denied.
 *
 * Prereqs: `docker compose up` at the repo root, `npm install` here, and the
 * agent-action-tool binary (`cd core && cargo build --release`, or set
 * SAURONID_AGENT_ACTION_TOOL). See README.md.
 */

import { SauronIDClient, registerLlmAgent } from "@sauronid/agentic";

const CORE_URL = "http://localhost:3001";
const DEV_ADMIN_KEY = process.env.SAURON_ADMIN_KEY ?? "dev-only-admin-key-not-for-production"; // dev stack only

async function main(): Promise<void> {
    const client = new SauronIDClient({ baseUrl: CORE_URL, adminKey: DEV_ADMIN_KEY });

    // 1. Authenticate the human owner (dev-only password login, seeded user).
    const auth = await client.userAuth("alice@sauron.dev", "pass_alice");
    console.log(`user session ok, key_image=${auth.key_image.slice(0, 16)}...`);

    // 2. Register the agent. model + prompt + tools become the binding
    //    checksum; the Ed25519 PoP keypair never leaves this process.
    //    maxAmount + currency register a server-enforced payment cap.
    const agent = await registerLlmAgent(client, {
        userSession: auth.session,
        userKeyImage: auth.key_image,
        modelId: "claude-sonnet-4-5",
        systemPrompt: "You are a careful assistant.",
        tools: ["search"],
        intentScope: ["payment_initiation"],
        maxAmount: 5.0,
        currency: "EUR",
    });
    console.log(`registered agentId=${agent.agentId}`);
    console.log(`binding checksum =${agent.configDigest}`);

    // 3. A signed call (call-sig v2 headers: ts, nonce, body hash, digest).
    const resp = await agent.call("GET", `/agent/${agent.agentId}`);
    const record = await resp.json();
    console.log(`signed call -> ${resp.status}`);
    console.log(`server-stored checksum=${String(record.agent_checksum).slice(0, 24)}...`);

    // 4. A deliberately over-limit payment. The intent caps this agent at
    //    5.00 EUR, so the leash denies 2500.00 EUR server-side with the real
    //    "Requested amount ... exceeds intent maxAmount" message (see
    //    docs/site/guides/payments.md).
    const denial = await agent.authorizePayment({
        userSession: auth.session,
        amountMinor: 250_000, // 2500.00 EUR
        currency: "EUR",
        paymentRef: "quickstart-overlimit-001",
    });
    console.log(`payment attempt -> ${denial.status} (expected 403)`);
    console.log(`denial body: ${await denial.text()}`);
    if (denial.status !== 403) throw new Error("leash should have denied this payment");

    await agent.revoke(auth.session);
    console.log("agent revoked");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
