import { cookies } from "next/headers";
import { verifySession, SESSION_COOKIE } from "@/lib/session";

// GET → the current operator session (for the UI to render who is logged in +
// which tenants they may switch to). 401 when unauthenticated.
export async function GET(): Promise<Response> {
  const jar = await cookies();
  const session = verifySession(jar.get(SESSION_COOKIE)?.value);
  if (!session) {
    return Response.json({ ok: false, error: "not authenticated" }, { status: 401 });
  }
  return Response.json({
    ok: true,
    operator: session.op,
    tenants: session.tenants,
    super: session.super,
  });
}
