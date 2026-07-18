import { createHash, randomBytes, sign, type KeyObject } from "node:crypto";

export interface CallSigV2Input {
    agentId: string;
    privateKey: KeyObject;
    method: string;
    targetUri: string;
    body: string | Buffer;
    configDigest: string;
    tenantId?: string;
    audience?: string;
    contentType?: string;
    timestampMs?: number;
    nonce?: string;
}

function canonicalFields(domain: string, fields: Array<[string, string]>): Buffer {
    const chunks: Buffer[] = [];
    for (const value of [domain, ...fields.flatMap(([name, field]) => [name, field])]) {
        const bytes = Buffer.from(value, "utf8");
        const len = Buffer.alloc(4);
        len.writeUInt32BE(bytes.length);
        chunks.push(len, bytes);
    }
    return Buffer.concat(chunks);
}

/** The exact protocol-v2 encoding used by core and every supported SDK. */
export function signCallV2(input: CallSigV2Input): Record<string, string> {
    const timestamp = input.timestampMs ?? Date.now();
    const nonce = input.nonce ?? randomBytes(16).toString("hex");
    const tenant = input.tenantId ?? "default";
    const audience = input.audience ?? "sauron-core";
    const contentType = (input.contentType ?? "application/json").trim().toLowerCase();
    const bodyHash = createHash("sha256").update(input.body).digest("hex");
    const payload = canonicalFields("sauron.call.v2", [
        ["version", "2"],
        ["agent_id", input.agentId],
        ["tenant_id", tenant],
        ["audience", audience],
        ["method", input.method.toUpperCase()],
        ["target_uri", input.targetUri],
        ["content_type", contentType],
        ["body_sha256", bodyHash],
        ["config_digest", input.configDigest],
        ["timestamp_ms", String(timestamp)],
        ["nonce", nonce],
    ]);
    return {
        "x-sauron-agent-id": input.agentId,
        "x-sauron-call-ts": String(timestamp),
        "x-sauron-call-nonce": nonce,
        "x-sauron-call-sig": sign(null, payload, input.privateKey).toString("base64url"),
        "x-sauron-call-audience": audience,
        "x-sauron-protocol-version": "2",
        "x-sauron-agent-config-digest": input.configDigest,
        "x-sauron-tenant-id": tenant,
    };
}
