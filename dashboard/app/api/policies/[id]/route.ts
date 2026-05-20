// Same-origin proxy for `/v1/policy/:id` (GET full Policy + DELETE).

import { NextRequest } from "next/server";
import { proxyCoreV1 } from "../../_proxy";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCoreV1(`policy/${encodeURIComponent(id)}`, req, {
    method: "GET",
  });
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCoreV1(`policy/${encodeURIComponent(id)}`, req, {
    method: "DELETE",
  });
}
