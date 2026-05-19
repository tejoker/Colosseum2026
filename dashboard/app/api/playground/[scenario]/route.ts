import { NextRequest } from "next/server";

// Playground demo endpoints on the core were removed alongside the dead
// analytics path. The dashboard playground is now a client-side simulation
// only — return a deterministic stub so the UI renders correctly.
//
// When real demo endpoints land in the core, swap this for a `proxyCore(...)`
// call against the right /admin/* path.

const SCENARIO_RESULTS: Record<string, { result: "allowed" | "stopped"; status_code: number; detail: Record<string, unknown> }> = {
  normal: {
    result: "allowed",
    status_code: 200,
    detail: { scenario: "happy_path", note: "simulated — core demo endpoints not yet wired" },
  },
  replay: {
    result: "stopped",
    status_code: 409,
    detail: { scenario: "replay_attack", reason: "duplicate nonce detected (simulated)" },
  },
  scope: {
    result: "stopped",
    status_code: 403,
    detail: { scenario: "scope_escalation", reason: "intent outside mandate (simulated)" },
  },
  custom: {
    result: "stopped",
    status_code: 400,
    detail: { scenario: "custom", note: "custom scenarios require live core demo endpoints" },
  },
};

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ scenario: string }> }
) {
  const { scenario } = await params;
  const out = SCENARIO_RESULTS[scenario];
  if (!out) {
    return Response.json({ ok: false, error: "Unknown scenario" }, { status: 400 });
  }
  return Response.json(out);
}
