import { NextResponse } from "next/server";
import { coreApiUrl, requireAdminProxyAuth, adminKeyOrResponse } from "../../_adminProxy";

type ClientRecord = {
  name: string;
};

export async function GET(
  req: Request,
  { params }: { params: Promise<{ name: string }> }
) {
  const authError = requireAdminProxyAuth(req);
  if (authError) return authError;

  const adminKey = adminKeyOrResponse();
  if (typeof adminKey !== "string") return adminKey;

  const { name } = await params;
  try {
    const res = await fetch(`${coreApiUrl()}/admin/clients`, {
      headers: { "x-admin-key": adminKey },
    });
    const clients = (await res.json().catch(() => [])) as ClientRecord[];
    if (!res.ok) return NextResponse.json({ error: "upstream error" }, { status: res.status });
    const client = clients.find((c) => c.name === name);
    if (!client) return NextResponse.json({ error: "client not found" }, { status: 404 });
    return NextResponse.json(client);
  } catch {
    return NextResponse.json({ error: "backend unreachable" }, { status: 503 });
  }
}
