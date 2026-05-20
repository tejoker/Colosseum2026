// Dashboard tenant-context helper (Sprint 11.6).
//
// SauronID is multi-tenant on the core side (every `/v1/*` row is stamped
// with a tenant id). The dashboard scopes the active session through a
// cookie (`sauron_tenant_id`) that is mirrored in localStorage so that
// the in-browser switcher can react synchronously while server components
// + route handlers read it from the request headers.
//
// Layering:
//   * `currentTenant()` — browser-safe resolver: cookie → localStorage
//     → default. Safe to call from server (returns DEFAULT_TENANT when
//     `document` is undefined; server code reads the cookie via the
//     `cookies()` helper directly).
//   * `setCurrentTenant(id)` — writes cookie + localStorage and dispatches
//     a `sauron:tenant-changed` event so listeners can refresh state.
//   * `availableTenants()` — fetches the dashboard's `/api/tenants` proxy
//     (S11.6 ships an env-backed list; upgrade path is a real CRUD
//     endpoint on the core, see `dashboard/app/api/tenants/route.ts`).

/** Single source of truth for the dashboard's default tenant id. */
export const DEFAULT_TENANT = "default";

/** Name of the cookie holding the active tenant id (browser + middleware). */
export const TENANT_COOKIE = "sauron_tenant_id";

/** Header forwarded to the core to scope every `/v1/*` call. */
export const TENANT_HEADER = "x-sauron-tenant-id";

/** Key used in `localStorage` as a secondary store + sync signal across tabs. */
export const TENANT_STORAGE_KEY = "sauron_tenant_id";

/** Custom DOM event fired by `setCurrentTenant` so subscribers can react. */
export const TENANT_CHANGED_EVENT = "sauron:tenant-changed";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const raw = document.cookie || "";
  for (const piece of raw.split(";")) {
    const [k, ...rest] = piece.trim().split("=");
    if (k === name) {
      return decodeURIComponent(rest.join("=") || "");
    }
  }
  return null;
}

function writeCookie(name: string, value: string): void {
  if (typeof document === "undefined") return;
  // 1-year persistence; SameSite=Lax so server routes get it on top-level
  // navigations + same-origin fetches.
  const maxAge = 60 * 60 * 24 * 365;
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}

/**
 * Resolve the active tenant id. Browser-safe — returns DEFAULT_TENANT
 * when called from a server context (no `document`).
 */
export function currentTenant(): string {
  if (typeof document === "undefined") return DEFAULT_TENANT;
  const fromCookie = readCookie(TENANT_COOKIE);
  if (fromCookie && fromCookie.trim()) return fromCookie.trim();
  try {
    const fromStorage =
      typeof localStorage !== "undefined"
        ? localStorage.getItem(TENANT_STORAGE_KEY)
        : null;
    if (fromStorage && fromStorage.trim()) return fromStorage.trim();
  } catch {
    // localStorage may throw in some browsers (private mode etc.); fall through.
  }
  return DEFAULT_TENANT;
}

/**
 * Write the active tenant id (cookie + localStorage) and dispatch a
 * `sauron:tenant-changed` CustomEvent. No-op in non-browser contexts.
 */
export function setCurrentTenant(tenantId: string): void {
  if (!tenantId || !tenantId.trim()) return;
  const id = tenantId.trim();
  if (typeof document === "undefined") return;
  writeCookie(TENANT_COOKIE, id);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(TENANT_STORAGE_KEY, id);
    }
  } catch {
    // ignore localStorage write errors
  }
  try {
    if (typeof window !== "undefined" && typeof CustomEvent === "function") {
      window.dispatchEvent(
        new CustomEvent(TENANT_CHANGED_EVENT, { detail: { tenantId: id } })
      );
    }
  } catch {
    // ignore event-dispatch failure
  }
}

/**
 * Fetch the list of tenants the dashboard knows about. Backed by the
 * `/api/tenants` Next.js proxy route, which today derives its list from
 * the `SAURONID_TENANTS` env var (see route handler for the upgrade
 * path to a real tenant CRUD endpoint).
 *
 * Always includes `DEFAULT_TENANT` and de-duplicates.
 */
export async function availableTenants(): Promise<string[]> {
  try {
    const res = await fetch("/api/tenants", {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) return [DEFAULT_TENANT];
    const body = (await res.json()) as { tenants?: unknown };
    const raw = Array.isArray(body.tenants) ? body.tenants : [];
    const ids = raw
      .filter((v): v is string => typeof v === "string" && v.trim().length > 0)
      .map((v) => v.trim());
    const dedup = Array.from(new Set([DEFAULT_TENANT, ...ids]));
    return dedup;
  } catch {
    return [DEFAULT_TENANT];
  }
}
