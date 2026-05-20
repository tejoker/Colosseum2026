// Server-side proxy from the Next.js dashboard to the SauronID core.
//
// Architecture:
//   Browser → http://<host>:3000/api/X  (same-origin)
//          → this proxy
//          → http://localhost:3001/admin/X  (core, x-admin-key)
//
// The browser never sees the core URL. CORS is not a concern because the
// proxy runs server-side in Next.js.

const CORE_INTERNAL_URL = (
  process.env.SAURON_CORE_INTERNAL_URL ?? "http://localhost:3001"
).replace(/\/+$/, "");

/** Header the dashboard uses to scope every `/v1/*` + `/admin/*` call. */
const TENANT_HEADER = "x-sauron-tenant-id";
const TENANT_COOKIE = "sauron_tenant_id";

/**
 * Pull the tenant id from the incoming Request. Order of precedence:
 *   1. Explicit `x-sauron-tenant-id` header (set by Next.js middleware
 *      from the cookie, or by client fetchers via `lib/api.ts`).
 *   2. The `sauron_tenant_id` cookie (handles direct browser requests
 *      to the proxy that bypassed middleware — rare but cheap).
 *   3. `null` — caller decides whether to forward at all.
 */
function tenantFromRequest(req: Request): string | null {
  const direct = req.headers.get(TENANT_HEADER);
  if (direct && direct.trim()) return direct.trim();
  const cookie = req.headers.get("cookie") ?? "";
  for (const piece of cookie.split(";")) {
    const [k, ...rest] = piece.trim().split("=");
    if (k === TENANT_COOKIE) {
      const v = decodeURIComponent(rest.join("=") || "").trim();
      if (v) return v;
    }
  }
  return null;
}

function adminKey(): string {
  const k = process.env.SAURON_ADMIN_KEY;
  if (!k || !k.trim()) {
    throw new Error(
      "SAURON_ADMIN_KEY is not set on the dashboard server — required to call the core /admin/* surface."
    );
  }
  return k.trim();
}

export interface ProxyOpts {
  method?: string;
  body?: BodyInit | null;
  forwardQuery?: boolean; // default true
  extraHeaders?: Record<string, string>;
}

/**
 * Forward to `${CORE_INTERNAL_URL}/admin/${coreAdminPath}${incomingSearch}` with
 * `x-admin-key`. Returns a Response with the upstream body + status. On network
 * failure returns 503 `{ok:false, error:"upstream unreachable"}`.
 *
 * `coreAdminPath` MUST NOT start with a slash.
 */
export async function proxyCore(
  coreAdminPath: string,
  req: Request,
  opts: ProxyOpts = {}
): Promise<Response> {
  const method = (opts.method ?? "GET").toUpperCase();
  const forwardQuery = opts.forwardQuery ?? true;

  let search = "";
  if (forwardQuery) {
    try {
      search = new URL(req.url).search;
    } catch {
      search = "";
    }
  }

  const target = `${CORE_INTERNAL_URL}/admin/${coreAdminPath}${search}`;

  let key: string;
  try {
    key = adminKey();
  } catch (e) {
    return Response.json(
      { ok: false, error: e instanceof Error ? e.message : "admin key missing" },
      { status: 500 }
    );
  }

  const headers: Record<string, string> = {
    "x-admin-key": key,
    accept: "application/json",
    ...(opts.extraHeaders ?? {}),
  };
  if (opts.body && !headers["content-type"] && !headers["Content-Type"]) {
    headers["content-type"] = "application/json";
  }
  const tenant = tenantFromRequest(req);
  if (tenant && !headers[TENANT_HEADER]) {
    headers[TENANT_HEADER] = tenant;
  }

  try {
    const upstream = await fetch(target, {
      method,
      headers,
      body: opts.body ?? undefined,
      cache: "no-store",
    });
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        "content-type":
          upstream.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return Response.json(
      { ok: false, error: "upstream unreachable" },
      { status: 503 }
    );
  }
}

/**
 * GET helper used by route handlers that need to read+adapt the JSON shape
 * before responding. Returns parsed JSON on success, or a Response on failure
 * that the caller can return directly. Pass the incoming `Request` to forward
 * the tenant context to the core (the parameter is optional to preserve
 * existing call sites; tenant scoping is additive).
 */
export async function fetchCoreJson<T = unknown>(
  coreAdminPath: string,
  search = "",
  req?: Request
): Promise<{ ok: true; data: T } | { ok: false; response: Response }> {
  let key: string;
  try {
    key = adminKey();
  } catch (e) {
    return {
      ok: false,
      response: Response.json(
        { ok: false, error: e instanceof Error ? e.message : "admin key missing" },
        { status: 500 }
      ),
    };
  }
  const target = `${CORE_INTERNAL_URL}/admin/${coreAdminPath}${search}`;
  const headers: Record<string, string> = {
    "x-admin-key": key,
    accept: "application/json",
  };
  if (req) {
    const tenant = tenantFromRequest(req);
    if (tenant) headers[TENANT_HEADER] = tenant;
  }
  try {
    const upstream = await fetch(target, {
      headers,
      cache: "no-store",
    });
    if (!upstream.ok) {
      const text = await upstream.text();
      return {
        ok: false,
        response: new Response(text || `core ${upstream.status}`, {
          status: upstream.status,
          headers: { "content-type": "application/json" },
        }),
      };
    }
    const data = (await upstream.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      response: Response.json(
        { ok: false, error: "upstream unreachable" },
        { status: 503 }
      ),
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// /v1/* variants. Same admin-key auth, but mount point is `/v1/<prefix>/<path>`
// instead of `/admin/<path>` (used by /v1/policy/* and /v1/agents/*/spend).
// Additive — does NOT change the /admin/* helpers above.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Same as `proxyCore` but targets `${CORE_INTERNAL_URL}/v1/${corePath}` instead of
 * `${CORE_INTERNAL_URL}/admin/${corePath}`. `corePath` MUST NOT start with a slash.
 */
export async function proxyCoreV1(
  corePath: string,
  req: Request,
  opts: ProxyOpts = {}
): Promise<Response> {
  const method = (opts.method ?? "GET").toUpperCase();
  const forwardQuery = opts.forwardQuery ?? true;

  let search = "";
  if (forwardQuery) {
    try {
      search = new URL(req.url).search;
    } catch {
      search = "";
    }
  }

  const target = `${CORE_INTERNAL_URL}/v1/${corePath}${search}`;

  let key: string;
  try {
    key = adminKey();
  } catch (e) {
    return Response.json(
      { ok: false, error: e instanceof Error ? e.message : "admin key missing" },
      { status: 500 }
    );
  }

  const headers: Record<string, string> = {
    "x-admin-key": key,
    accept: "application/json",
    ...(opts.extraHeaders ?? {}),
  };
  if (opts.body && !headers["content-type"] && !headers["Content-Type"]) {
    headers["content-type"] = "application/json";
  }
  const tenant = tenantFromRequest(req);
  if (tenant && !headers[TENANT_HEADER]) {
    headers[TENANT_HEADER] = tenant;
  }

  try {
    const upstream = await fetch(target, {
      method,
      headers,
      body: opts.body ?? undefined,
      cache: "no-store",
    });
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        "content-type":
          upstream.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return Response.json(
      { ok: false, error: "upstream unreachable" },
      { status: 503 }
    );
  }
}

/**
 * Same as `fetchCoreJson` but targets `${CORE_INTERNAL_URL}/v1/${corePath}`.
 * Pass `req` to forward the tenant context to the core.
 */
export async function fetchCoreV1Json<T = unknown>(
  corePath: string,
  search = "",
  req?: Request
): Promise<{ ok: true; data: T } | { ok: false; response: Response }> {
  let key: string;
  try {
    key = adminKey();
  } catch (e) {
    return {
      ok: false,
      response: Response.json(
        { ok: false, error: e instanceof Error ? e.message : "admin key missing" },
        { status: 500 }
      ),
    };
  }
  const target = `${CORE_INTERNAL_URL}/v1/${corePath}${search}`;
  const headers: Record<string, string> = {
    "x-admin-key": key,
    accept: "application/json",
  };
  if (req) {
    const tenant = tenantFromRequest(req);
    if (tenant) headers[TENANT_HEADER] = tenant;
  }
  try {
    const upstream = await fetch(target, {
      headers,
      cache: "no-store",
    });
    if (!upstream.ok) {
      const text = await upstream.text();
      return {
        ok: false,
        response: new Response(text || `core ${upstream.status}`, {
          status: upstream.status,
          headers: { "content-type": "application/json" },
        }),
      };
    }
    const data = (await upstream.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      response: Response.json(
        { ok: false, error: "upstream unreachable" },
        { status: 503 }
      ),
    };
  }
}

export { CORE_INTERNAL_URL, TENANT_HEADER, TENANT_COOKIE };
