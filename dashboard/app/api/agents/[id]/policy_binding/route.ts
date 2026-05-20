// Sprint 10 — server-side agent → policy binding proxy.
//
// Browser → /api/agents/:id/policy_binding (same-origin)
//        → this route → core `/v1/agents/:id/policy_binding` (x-admin-key auto-injected).
//
// All three verbs (GET/POST/DELETE) forward through `proxyCoreV1` so the
// admin key never leaks to the browser. The path segment is URL-encoded
// to keep an agent_id with `:` / `/` characters from breaking out of the
// expected sub-tree.
import { NextRequest } from "next/server";
import { proxyCoreV1 } from "../../../_proxy";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCoreV1(`agents/${encodeURIComponent(id)}/policy_binding`, req, {
    method: "GET",
  });
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await req.text();
  return proxyCoreV1(`agents/${encodeURIComponent(id)}/policy_binding`, req, {
    method: "POST",
    body,
    extraHeaders: { "content-type": "application/json" },
  });
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCoreV1(`agents/${encodeURIComponent(id)}/policy_binding`, req, {
    method: "DELETE",
  });
}
