import { NextResponse } from "next/server";

export function coreApiUrl(): string {
  return (
    process.env.SAURON_CORE_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    "http://localhost:3001"
  );
}

export function requireAdminProxyAuth(req: Request): NextResponse | null {
  // SAURONID_* are the canonical env names; TRUSTAI_* are accepted for one release as
  // backwards-compatibility aliases.
  const allowUnauth =
    process.env.SAURONID_ALLOW_UNAUTHENTICATED_ADMIN_PROXY === "1" ||
    process.env.TRUSTAI_ALLOW_UNAUTHENTICATED_ADMIN_PROXY === "1";
  if (allowUnauth) {
    return null;
  }

  const token =
    process.env.SAURONID_ADMIN_PROXY_TOKEN || process.env.TRUSTAI_ADMIN_PROXY_TOKEN;
  if (!token) {
    if (process.env.NODE_ENV === "production") {
      return NextResponse.json(
        {
          error:
            "Admin proxy disabled: SAURONID_ADMIN_PROXY_TOKEN (or legacy TRUSTAI_ADMIN_PROXY_TOKEN) is not configured",
        },
        { status: 503 }
      );
    }
    return null;
  }

  const header =
    req.headers.get("x-sauronid-admin-token") || req.headers.get("x-trustai-admin-token");
  const cookieParts = req.headers
    .get("cookie")
    ?.split(";")
    .map((part) => part.trim()) ?? [];
  const cookie =
    cookieParts
      .find((part) => part.startsWith("sauronid_admin_token="))
      ?.slice("sauronid_admin_token=".length) ??
    cookieParts
      .find((part) => part.startsWith("trustai_admin_token="))
      ?.slice("trustai_admin_token=".length);

  if (header === token || cookie === token) {
    return null;
  }

  return NextResponse.json({ error: "Admin proxy unauthorized" }, { status: 401 });
}

export function adminKeyOrResponse(): string | NextResponse {
  const adminKey = process.env.SAURON_ADMIN_KEY;
  if (!adminKey) {
    return NextResponse.json(
      { error: "SAURON_ADMIN_KEY is not configured for this proxy" },
      { status: 500 }
    );
  }
  return adminKey;
}

export async function fetchAdminJson(
  req: Request,
  path: string,
  init: RequestInit & { next?: { revalidate?: number } } = {}
): Promise<NextResponse> {
  const authError = requireAdminProxyAuth(req);
  if (authError) return authError;

  const adminKey = adminKeyOrResponse();
  if (typeof adminKey !== "string") return adminKey;

  try {
    const headers = new Headers(init.headers);
    headers.set("x-admin-key", adminKey);
    const res = await fetch(`${coreApiUrl()}${path}`, {
      ...init,
      headers,
    });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: "backend unreachable" }, { status: 503 });
  }
}
