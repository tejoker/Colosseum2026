import { cookies } from "next/headers";
import {
  authenticate,
  signSession,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
} from "@/lib/session";

const attempts = new Map<string, { count: number; resetAt: number }>();
const WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 8;

// POST { operator, password } → sets the signed, httpOnly session cookie.
// This route is exempt from the middleware auth gate (you can't log in if the
// gate blocks the login call).
export async function POST(req: Request): Promise<Response> {
  let body: { operator?: string; password?: string };
  try {
    body = (await req.json()) as { operator?: string; password?: string };
  } catch {
    return Response.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }
  const op = (body.operator ?? "").trim();
  const password = body.password ?? "";
  if (!op || !password) {
    return Response.json(
      { ok: false, error: "operator and password are required" },
      { status: 400 }
    );
  }

  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const key = `${forwarded || "unknown"}:${op}`;
  const now = Date.now();
  const prior = attempts.get(key);
  if (prior && prior.resetAt > now && prior.count >= MAX_ATTEMPTS) {
    return Response.json({ ok: false, error: "too many login attempts" }, { status: 429 });
  }
  if (!prior || prior.resetAt <= now) attempts.set(key, { count: 0, resetAt: now + WINDOW_MS });

  let auth: { tenants: string[]; super: boolean } | null;
  try {
    auth = authenticate(op, password);
  } catch (e) {
    // sessionSecret()/config errors surface as 500 (fail closed).
    return Response.json(
      { ok: false, error: e instanceof Error ? e.message : "auth misconfigured" },
      { status: 500 }
    );
  }
  if (!auth) {
    const current = attempts.get(key)!;
    current.count += 1;
    return Response.json({ ok: false, error: "invalid credentials" }, { status: 401 });
  }
  attempts.delete(key);

  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const token = signSession({ op, tenants: auth.tenants, super: auth.super, exp });
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  return Response.json({ ok: true, operator: op, tenants: auth.tenants, super: auth.super });
}
