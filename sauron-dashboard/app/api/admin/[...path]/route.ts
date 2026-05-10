import { NextResponse, NextRequest } from "next/server";
import { adminKeyOrResponse, coreApiUrl, requireAdminProxyAuth } from "../../_adminProxy";

/**
 * Server-side proxy for all /admin/* endpoints.
 * Injects SAURON_ADMIN_KEY — never exposed to the browser.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const authError = requireAdminProxyAuth(req);
  if (authError) return authError;

  const { path } = await params;
  const adminKey = adminKeyOrResponse();
  if (typeof adminKey !== "string") return adminKey;
  const upstream = `${coreApiUrl()}/admin/${path.join("/")}`;

  try {
    const res = await fetch(upstream, { headers: { "x-admin-key": adminKey } });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: "upstream error" }, { status: 503 });
  }
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const authError = requireAdminProxyAuth(req);
  if (authError) return authError;

  const { path } = await params;
  const adminKey = adminKeyOrResponse();
  if (typeof adminKey !== "string") return adminKey;
  const upstream = `${coreApiUrl()}/admin/${path.join("/")}`;
  const body = await req.text();

  try {
    const res = await fetch(upstream, {
      method: "POST",
      headers: { "x-admin-key": adminKey, "content-type": "application/json" },
      body,
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: "upstream error" }, { status: 503 });
  }
}
