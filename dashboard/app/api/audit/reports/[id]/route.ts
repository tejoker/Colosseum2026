// Sprint 19-20: single-report proxy.
//
// Forwards GET /api/audit/reports/:id → core GET /v1/audit/reports/:id.

import { NextRequest } from "next/server";
import { proxyCoreV1 } from "../../../_proxy";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCoreV1(`audit/reports/${encodeURIComponent(id)}`, req, {
    method: "GET",
  });
}
