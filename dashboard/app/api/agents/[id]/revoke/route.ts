import { NextRequest, NextResponse } from "next/server";

const CORE_URL = process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  const { id } = await params;
  try {
    const res = await fetch(`${CORE_URL}/api/v1/agents/${id}/revoke`, {
      method: "POST",
    });
    const body = await res.text();
    return new NextResponse(body, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("Content-Type") ?? "application/json" },
    });
  } catch {
    return NextResponse.json({ ok: false, error: "upstream unavailable" }, { status: 503 });
  }
}
