// Same-origin proxy for `POST /v1/policy/evaluate`. The path id is folded into
// the JSON body as `policy_id` so callers don't have to repeat it.

import { NextRequest } from "next/server";
import { proxyCoreV1 } from "../../../_proxy";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  let payload: Record<string, unknown> = {};
  try {
    payload = (await req.json()) as Record<string, unknown>;
  } catch {
    return Response.json(
      { ok: false, error: "invalid JSON body" },
      { status: 400 }
    );
  }
  // Force the policy_id from the path; ignore any in-body override.
  payload.policy_id = id;
  return proxyCoreV1("policy/evaluate", req, {
    method: "POST",
    body: JSON.stringify(payload),
    extraHeaders: { "content-type": "application/json" },
    forwardQuery: false,
  });
}
