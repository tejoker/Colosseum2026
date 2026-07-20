// /api/tenants — list known tenant ids for the in-dashboard switcher, and
// register new names for it.
//
// S11.6 ship: the core has no formal tenant lifecycle endpoint — tenants
// become real on first use (first request carrying the id). The switcher list
// is derived from the `SAURONID_TENANTS` env var (comma-separated) plus names
// registered at runtime via POST below, which are kept in a browser cookie
// (`sauron_known_tenants`) because the dashboard has no persistence layer.
// The `default` tenant is always present so a freshly-provisioned dashboard
// still renders the switcher.
//
// Upgrade path when the core grows a real tenant CRUD surface:
//   1. Add a `/admin/tenants` GET to the core that returns
//      `[{ id, label, created_at, ... }]`.
//   2. Replace the env+cookie merge below with a `fetchCoreJson("tenants")`.
//   3. Optionally fall back to the env list if the core endpoint 404s.

import { DEFAULT_TENANT } from "@/lib/tenant";

const KNOWN_TENANTS_COOKIE = "sauron_known_tenants";
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_REGISTERED = 64;

function parseEnvTenants(): string[] {
  const raw = process.env.SAURONID_TENANTS;
  if (!raw || !raw.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Names registered from the Provision page, stored in a per-browser cookie. */
function parseCookieTenants(req: Request): string[] {
  const cookie = req.headers.get("cookie") ?? "";
  for (const piece of cookie.split(";")) {
    const [k, ...rest] = piece.trim().split("=");
    if (k === KNOWN_TENANTS_COOKIE) {
      try {
        const parsed = JSON.parse(decodeURIComponent(rest.join("=") || ""));
        if (Array.isArray(parsed)) {
          return parsed.filter(
            (t): t is string => typeof t === "string" && TENANT_RE.test(t)
          );
        }
      } catch {
        return [];
      }
    }
  }
  return [];
}

function knownTenants(req: Request): string[] {
  return Array.from(
    new Set([DEFAULT_TENANT, ...parseEnvTenants(), ...parseCookieTenants(req)])
  );
}

export async function GET(req: Request) {
  const isSuper = req.headers.get("x-sauron-admin-super") === "1";
  const authorized = new Set(
    (req.headers.get("x-sauron-admin-tenants") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const all = knownTenants(req);
  const tenants = isSuper ? all : all.filter((t) => authorized.has(t));
  return Response.json(
    { tenants },
    {
      headers: {
        "content-type": "application/json",
        // dashboard switcher polls on mount; keep this fresh.
        "cache-control": "no-store",
      },
    }
  );
}

// POST /api/tenants — register a tenant name for the switcher (super only).
//
// The core creates tenants implicitly on first use; this only records the
// name so it shows up in the switcher of THIS browser. Honest bookkeeping,
// not a core mutation.
export async function POST(req: Request) {
  if (req.headers.get("x-sauron-admin-super") !== "1") {
    return Response.json(
      { ok: false, error: "registering tenants requires a super operator" },
      { status: 403 }
    );
  }
  let name = "";
  try {
    const body = (await req.json()) as { name?: unknown };
    name = typeof body.name === "string" ? body.name.trim() : "";
  } catch {
    return Response.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }
  if (!TENANT_RE.test(name)) {
    return Response.json(
      { ok: false, error: "tenant id must match [A-Za-z0-9_-]{1,64}" },
      { status: 400 }
    );
  }
  const registered = Array.from(
    new Set([...parseCookieTenants(req), name])
  ).slice(-MAX_REGISTERED);
  const cookieValue = encodeURIComponent(JSON.stringify(registered));
  return Response.json(
    { ok: true, tenants: Array.from(new Set([...knownTenants(req), name])) },
    {
      headers: {
        "cache-control": "no-store",
        "set-cookie": `${KNOWN_TENANTS_COOKIE}=${cookieValue}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax; HttpOnly`,
      },
    }
  );
}
