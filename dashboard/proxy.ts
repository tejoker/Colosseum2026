// Next.js proxy — dashboard auth + tenant-isolation gate.
//
// This is the single enforcement point. It runs on the Edge runtime, so it
// verifies the operator session with Web Crypto (the API routes sign it with
// node:crypto over the identical HMAC-SHA256 payload — see lib/session.ts).
//
//   * /api/*   → 401 JSON without a valid session (the proxy holds the god-mode
//                admin key; it must never be reachable anonymously).
//   * pages    → redirect to /login without a valid session.
//   * tenant   → derived from the SESSION's authorized tenants, NOT from a
//                client-settable cookie. The resolved tenant is written to
//                `x-sauron-tenant-id` (overwriting any client value) so the
//                proxy + server components see only an authorized tenant.
//
// Exempt (no session required): /api/auth/*, /login, static assets. The
// dashboard health route includes operator data and therefore stays protected;
// use the core's minimal public `/health` endpoint for liveness probes.

import { NextRequest, NextResponse } from "next/server";

const SESSION_COOKIE = "sauron_session";
const TENANT_COOKIE = "sauron_tenant_id";
const TENANT_HEADER = "x-sauron-tenant-id";

interface Session {
  op: string;
  tenants: string[];
  super: boolean;
  exp: number;
}

function sessionSecret(): string {
  const s = process.env.SAURON_DASHBOARD_SESSION_SECRET;
  if (s && s.trim()) return s.trim();
  if (process.env.NODE_ENV !== "production") {
    return "sauron-dev-dashboard-session-secret-do-not-use-in-prod";
  }
  // No secret in prod → every session is invalid (fail closed). Callers get
  // 401 / redirected; the login route surfaces the real 500.
  return "";
}

function b64uToUint8(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyEdge(token: string | undefined): Promise<Session | null> {
  if (!token) return null;
  const secret = sessionSecret();
  if (!secret) return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      b64uToUint8(mac),
      new TextEncoder().encode(payload)
    );
    if (!ok) return null;
    const s = JSON.parse(new TextDecoder().decode(b64uToUint8(payload))) as Session;
    if (typeof s.exp !== "number" || s.exp < Math.floor(Date.now() / 1000)) return null;
    if (!Array.isArray(s.tenants) || typeof s.op !== "string") return null;
    return s;
  } catch {
    return null;
  }
}

/** The tenant an operator may act on for this request, or null if disallowed. */
function resolveTenant(session: Session, requested: string | null): string | null {
  const want = requested?.trim() || "";
  if (session.super) {
    return want || session.tenants[0] || "default";
  }
  if (want) {
    return session.tenants.includes(want) ? want : null;
  }
  return session.tenants[0] ?? null;
}

function isExempt(pathname: string): boolean {
  return (
    pathname.startsWith("/api/auth/") ||
    pathname === "/login" ||
    pathname.startsWith("/_next/") ||
    pathname === "/favicon.ico" ||
    pathname === "/logo.svg"
  );
}

export async function proxy(req: NextRequest): Promise<NextResponse> {
  const { pathname } = req.nextUrl;
  if (isExempt(pathname)) return NextResponse.next();

  const session = await verifyEdge(req.cookies.get(SESSION_COOKIE)?.value);
  const isApi = pathname.startsWith("/api/");

  if (!session) {
    if (isApi) {
      return NextResponse.json({ ok: false, error: "authentication required" }, { status: 401 });
    }
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = `?next=${encodeURIComponent(pathname)}`;
    return NextResponse.redirect(url);
  }

  // Tenant is bound to the authenticated operator.
  const requested =
    req.headers.get(TENANT_HEADER) || req.cookies.get(TENANT_COOKIE)?.value || null;
  const tenant = resolveTenant(session, requested);
  if (tenant === null) {
    if (isApi) {
      return NextResponse.json(
        { ok: false, error: `operator '${session.op}' is not authorized for the requested tenant` },
        { status: 403 }
      );
    }
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  const headers = new Headers(req.headers);
  headers.set(TENANT_HEADER, tenant); // authoritative; overwrites any client value
  headers.set("x-sauron-operator", session.op);
  // The server-side proxy turns this authenticated session into a short-lived
  // admin JWT. These headers are written by middleware (never trusted from the
  // browser) so a tenant-locked operator cannot inherit the proxy's static
  // cross-tenant admin key.
  headers.set("x-sauron-admin-super", session.super ? "1" : "0");
  headers.set("x-sauron-admin-tenants", session.tenants.join(","));
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|logo.svg).*)"],
};
