import { NextRequest } from "next/server";
import { proxyCore } from "../../../_proxy";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyCore(`agents/${encodeURIComponent(id)}/revoke`, req, {
    method: "POST",
  });
}
