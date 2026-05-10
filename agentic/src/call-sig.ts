/**
 * SauronID per-call signature (DPoP-style request binding).
 *
 * Each protected call carries an Ed25519 signature over:
 *
 *   method | path | sha256(body) | timestamp_ms | nonce
 *
 * signed by the agent's PoP private key. Server verifies with the registered
 * `pop_public_key_b64u` and consumes the nonce atomically (single-use).
 *
 * Closes the gap that A-JWT + PoP-on-challenge does not: a captured A-JWT
 * cannot be replayed against a different endpoint or with a mutated body.
 */

import * as crypto from "crypto";

export interface CallSignatureHeaders {
    "x-sauron-agent-id": string;
    "x-sauron-call-ts": string;
    "x-sauron-call-nonce": string;
    "x-sauron-call-sig": string;
    "x-sauron-agent-config-digest": string;
}

export interface SignCallInput {
    /** Agent ID (must match the agent whose pop_public_key_b64u is registered server-side). */
    agentId: string;
    /** HTTP method, uppercase. */
    method: string;
    /** Path component of the URL (no scheme/host/query). */
    path: string;
    /** Raw request body bytes (`""` for GET). Must match exactly what the HTTP client sends. */
    body: string | Uint8Array;
    /** Ed25519 private key (`crypto.KeyObject` from `crypto.generateKeyPairSync("ed25519")`). */
    privateKey: crypto.KeyObject;
    /**
     * Server-computed checksum the agent was registered with, of the form
     * `sha256:<hex>`. Required (Gap 4 enforcement). The agent runtime is
     * expected to know its own registered config digest and surface it on
     * every call. If this value drifts from the server-stored
     * `agents.agent_checksum`, the call is rejected with 401 — preventing a
     * silent system-prompt / tool-list flip.
     */
    agentConfigDigest: string;
    /** Optional override for timestamp (unix ms). Default: now. */
    timestampMs?: number;
    /** Optional override for nonce. Default: 16 random bytes hex. */
    nonce?: string;
}

/**
 * Compute the SauronID per-call signature headers for the given request.
 *
 * Caller is responsible for ensuring `body` is byte-for-byte identical to the
 * body the HTTP client will send (including JSON whitespace).
 */
export function signCall(input: SignCallInput): CallSignatureHeaders {
    const ts = input.timestampMs ?? Date.now();
    const nonce = input.nonce ?? crypto.randomBytes(16).toString("hex");

    const bodyBytes =
        typeof input.body === "string" ? Buffer.from(input.body, "utf8") : Buffer.from(input.body);
    const bodyHashHex = crypto.createHash("sha256").update(bodyBytes).digest("hex");

    const signingPayload = `${input.method}|${input.path}|${bodyHashHex}|${ts}|${nonce}`;

    const sig = crypto.sign(null, Buffer.from(signingPayload, "utf8"), input.privateKey);
    const sigB64u = sig.toString("base64url");

    return {
        "x-sauron-agent-id": input.agentId,
        "x-sauron-call-ts": String(ts),
        "x-sauron-call-nonce": nonce,
        "x-sauron-call-sig": sigB64u,
        "x-sauron-agent-config-digest": input.agentConfigDigest,
    };
}

/**
 * Convenience: extract the b64url public key matching a private KeyObject.
 * Useful for registering the agent's pop_public_key_b64u server-side.
 */
export function popPublicKeyB64Url(privateKey: crypto.KeyObject): string {
    const publicKey = crypto.createPublicKey(privateKey);
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) {
        throw new Error("failed to export Ed25519 public JWK x parameter");
    }
    return jwk.x;
}
