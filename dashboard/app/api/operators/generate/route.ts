// /api/operators/generate — dashboard-local operator-record generator.
//
// Dashboard operators live in the `SAURON_DASHBOARD_OPERATORS` env var, which
// cannot be mutated at runtime. This route therefore generates (server-side,
// with node:crypto scrypt — same parameters `lib/session.ts` verifies with)
// the JSON fragment an admin pastes into that env var. Nothing is stored and
// no core call is made; the fragment grants nothing until someone with env
// access deploys it. Requires an authenticated session (middleware gate).

import { randomBytes, scryptSync } from "node:crypto";

const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MIN_PASSWORD_LEN = 12;

interface GenerateBody {
  name?: unknown;
  password?: unknown;
  tenants?: unknown;
  super?: unknown;
}

export async function POST(req: Request): Promise<Response> {
  let body: GenerateBody;
  try {
    body = (await req.json()) as GenerateBody;
  } catch {
    return Response.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }

  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!NAME_RE.test(name)) {
    return Response.json(
      { ok: false, error: "name must match [A-Za-z0-9_-]{1,64}" },
      { status: 400 }
    );
  }
  const password = typeof body.password === "string" ? body.password : "";
  if (password.length < MIN_PASSWORD_LEN) {
    return Response.json(
      { ok: false, error: `password must be at least ${MIN_PASSWORD_LEN} characters` },
      { status: 400 }
    );
  }
  const isSuper = body.super === true;
  const tenants = Array.isArray(body.tenants)
    ? body.tenants
        .filter((t): t is string => typeof t === "string")
        .map((t) => t.trim())
        .filter(Boolean)
    : [];
  if (tenants.some((t) => !TENANT_RE.test(t))) {
    return Response.json(
      { ok: false, error: "each tenant id must match [A-Za-z0-9_-]{1,64}" },
      { status: 400 }
    );
  }
  if (!isSuper && tenants.length === 0) {
    return Response.json(
      { ok: false, error: "a non-super operator needs at least one tenant" },
      { status: 400 }
    );
  }

  // Same derivation lib/session.ts `authenticate()` verifies:
  // `base64(salt):base64(scrypt(password, salt))`, N=16384 r=8 p=1.
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
  });
  const record = {
    password_scrypt: `${salt.toString("base64")}:${hash.toString("base64")}`,
    tenants,
    super: isSuper,
  };

  return Response.json(
    {
      ok: true,
      name,
      record,
      // Fragment to merge into the SAURON_DASHBOARD_OPERATORS JSON object.
      fragment: JSON.stringify({ [name]: record }),
    },
    { headers: { "cache-control": "no-store" } }
  );
}
