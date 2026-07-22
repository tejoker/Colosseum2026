// Dashboard operator session (auth + tenant binding).
//
// The dashboard proxies to the core with the god-mode `x-admin-key`. Before
// this module there was NO authentication and the active tenant was a
// client-settable cookie — so any anonymous request got god-mode and any
// operator could self-assert any tenant. This module fixes both:
//
//   * Operators authenticate (`/api/auth/login`) against `SAURON_DASHBOARD_OPERATORS`.
//   * A signed, httpOnly session cookie carries the operator's authorized
//     tenants + super flag. `proxy.ts` verifies it (Web Crypto) and
//     derives the tenant from the SESSION, not from client input.
//
// Signing here uses node:crypto (API routes run in the Node runtime). The Edge
// Proxy verifies with Web Crypto over the identical HMAC-SHA256 payload.

import { createHmac, createHash, scryptSync, timingSafeEqual } from "crypto";

export const SESSION_COOKIE = "sauron_session";
export const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8h operator session

export interface Session {
  /** operator id (login name) */
  op: string;
  /** tenant ids this operator may act on */
  tenants: string[];
  /** true → may act on ANY tenant (maps to the core's cross-tenant admin) */
  super: boolean;
  /** unix expiry (seconds) */
  exp: number;
}

/** Signing/verification secret. Fail-closed in production, dev-derived locally. */
export function sessionSecret(): string {
  const s = process.env.SAURON_DASHBOARD_SESSION_SECRET;
  if (s && s.trim()) return s.trim();
  if (process.env.NODE_ENV !== "production") {
    return "sauron-dev-dashboard-session-secret-do-not-use-in-prod";
  }
  throw new Error(
    "SAURON_DASHBOARD_SESSION_SECRET is required in production (dashboard auth would be unsigned)."
  );
}

export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function b64u(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

/** `base64url(json).base64url(HMAC-SHA256(payload))` */
export function signSession(s: Session): string {
  const payload = b64u(JSON.stringify(s));
  const mac = createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
  return `${payload}.${mac}`;
}

/** Verify signature + expiry. Returns the session or null. Constant-time MAC compare. */
export function verifySession(token: string | undefined | null): Session | null {
  if (!token) return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const s = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
    if (typeof s.exp !== "number" || s.exp < Math.floor(Date.now() / 1000)) return null;
    if (!Array.isArray(s.tenants) || typeof s.op !== "string") return null;
    return s;
  } catch {
    return null;
  }
}

interface OperatorRecord {
  /** `base64(salt):base64(scrypt(password, salt))`; required in production. */
  password_scrypt?: string;
  /** Legacy development-only format. Never accept this in production. */
  password_sha256?: string;
  tenants?: string[];
  super?: boolean;
}

/**
 * Operator directory from `SAURON_DASHBOARD_OPERATORS` (JSON:
 * `{"<op>":{"password_scrypt":"<salt_b64>:<hash_b64>","tenants":["t1"],"super":false}}`).
 * Dev with no config → a single `dev`/`dev` super operator so the local demo
 * works. Production with no config → nobody can log in (fail closed).
 */
function operators(): Record<string, OperatorRecord> {
  const raw = process.env.SAURON_DASHBOARD_OPERATORS;
  if (raw && raw.trim()) {
    try {
      return JSON.parse(raw) as Record<string, OperatorRecord>;
    } catch {
      return {};
    }
  }
  if (process.env.NODE_ENV !== "production") {
    return { dev: { password_sha256: sha256Hex("dev"), tenants: ["default"], super: true } };
  }
  return {};
}

/** Verify operator credentials. Returns their tenant grant, or null. */
export function authenticate(
  op: string,
  password: string
): { tenants: string[]; super: boolean } | null {
  const rec = operators()[op];
  if (!rec) return null;
  let valid = false;
  if (rec.password_scrypt) {
    const [saltB64, hashB64] = rec.password_scrypt.split(":", 2);
    try {
      const salt = Buffer.from(saltB64, "base64");
      const want = Buffer.from(hashB64, "base64");
      const got = scryptSync(password, salt, want.length, {
        N: 16_384,
        r: 8,
        p: 1,
        maxmem: 32 * 1024 * 1024,
      });
      valid = got.length === want.length && timingSafeEqual(got, want);
    } catch {
      valid = false;
    }
  } else if (process.env.NODE_ENV !== "production" && rec.password_sha256) {
    const got = Buffer.from(sha256Hex(password));
    const want = Buffer.from(rec.password_sha256);
    valid = got.length === want.length && timingSafeEqual(got, want);
  }
  if (!valid) return null;
  return { tenants: rec.tenants ?? [], super: !!rec.super };
}
