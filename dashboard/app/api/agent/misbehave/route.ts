import { NextRequest } from "next/server";

const RUNNER = process.env.AGENT_RUNNER_URL || "http://127.0.0.1:8765";

export async function POST(req: NextRequest) {
  const body = await req.text();
  try {
    const r = await fetch(`${RUNNER}/misbehave`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      cache: "no-store",
    });
    return new Response(await r.text(), {
      status: r.status,
      headers: { "content-type": "application/json" },
    });
  } catch {
    return Response.json(
      { error: "agent runner unreachable — is the GPU-box runner + tunnel up?" },
      { status: 503 }
    );
  }
}
