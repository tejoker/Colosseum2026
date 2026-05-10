import { NextResponse } from "next/server";
import { adminKeyOrResponse, coreApiUrl, requireAdminProxyAuth } from "../../_adminProxy";

export async function GET(req: Request, { params }: { params: Promise<{ name: string }> }) {
  const authError = requireAdminProxyAuth(req);
  if (authError) return authError;

  const { name } = await params;
  const adminKey = adminKeyOrResponse();
  if (typeof adminKey !== "string") return adminKey;

  try {
    const res = await fetch(
      `${coreApiUrl()}/admin/site/${encodeURIComponent(name)}/zkp_proofs`,
      { headers: { "x-admin-key": adminKey } }
    );
    if (!res.ok) return NextResponse.json([], { status: res.status });
    return NextResponse.json(await res.json());
  } catch {
    return NextResponse.json([], { status: 503 });
  }
}
