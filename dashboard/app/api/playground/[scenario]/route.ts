import { NextRequest } from "next/server";

const CORE_URL = process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";

const SCENARIO_MAP: Record<string, string> = {
  normal:  "happy_path",
  replay:  "replay_attack",
  scope:   "scope_escalation",
  custom:  "custom",
};

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ scenario: string }> }
) {
  const { scenario } = await params;
  const mapped = SCENARIO_MAP[scenario];

  if (!mapped) {
    return Response.json({ ok: false, error: "Unknown scenario" }, { status: 400 });
  }

  try {
    const res = await fetch(`${CORE_URL}/api/v1/demo/${mapped}`, { method: "POST" });
    const json = await res.json() as unknown;
    return Response.json({
      result: res.ok ? "allowed" : "stopped",
      status_code: res.status,
      detail: json,
    });
  } catch {
    return Response.json(
      { result: "stopped", status_code: 0, detail: { error: "Core unreachable" } },
      { status: 503 }
    );
  }
}
