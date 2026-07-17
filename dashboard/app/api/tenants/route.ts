// /api/tenants — list known tenant ids for the in-dashboard switcher.
//
// S11.6 ship: the core has no formal tenant lifecycle endpoint. We derive
// the list from the `SAURONID_TENANTS` env var (comma-separated). The
// `default` tenant is always present so a freshly-provisioned dashboard
// still renders the switcher.
//
// Upgrade path when the core grows a real tenant CRUD surface:
//   1. Add a `/admin/tenants` GET to the core that returns
//      `[{ id, label, created_at, ... }]`.
//   2. Replace the env parse below with a `fetchCoreJson("tenants")` call.
//   3. Optionally fall back to the env list if the core endpoint 404s.
//
// Cohort/customer derivation (Option B in the design doc) is intentionally
// deferred — it requires aggregating distinct `tenant_id` values across
// `customer_stats` + cohort tables which the core does not yet expose in a
// single endpoint.

import { DEFAULT_TENANT } from "@/lib/tenant";

function parseEnvTenants(): string[] {
  const raw = process.env.SAURONID_TENANTS;
  if (!raw || !raw.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export async function GET(req: Request) {
  const envTenants = parseEnvTenants();
  const isSuper = req.headers.get("x-sauron-admin-super") === "1";
  const authorized = new Set(
    (req.headers.get("x-sauron-admin-tenants") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const tenants = isSuper
    ? Array.from(new Set([DEFAULT_TENANT, ...envTenants]))
    : Array.from(new Set([DEFAULT_TENANT, ...envTenants])).filter((t) => authorized.has(t));
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
