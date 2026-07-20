// /api/keys/issue — mint a scoped, tenant-locked SDK admin JWT via the core.
//
// Forwards to core `POST /admin/keys/issue`. Super operators only: the
// `x-sauron-admin-super` header is written by `middleware.ts` from the
// verified session (never trusted from the browser), so checking it here IS
// checking the session. The core re-checks on its side (cross-tenant super
// principal required), so this gate is defense-in-depth, not the only wall.

import { proxyCore } from "../../_proxy";

export async function POST(req: Request): Promise<Response> {
  if (req.headers.get("x-sauron-admin-super") !== "1") {
    return Response.json(
      { ok: false, error: "issuing SDK admin keys requires a super operator" },
      { status: 403 }
    );
  }
  const body = await req.text();
  return proxyCore("keys/issue", req, {
    method: "POST",
    body,
    forwardQuery: false,
  });
}
