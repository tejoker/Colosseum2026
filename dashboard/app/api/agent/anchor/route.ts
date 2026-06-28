import { NextRequest } from "next/server";
import { proxyCore } from "../../_proxy";

// Trigger a real Bitcoin (OpenTimestamps) anchor batch over the agents' actions.
export async function POST(req: NextRequest) {
  return proxyCore("anchor/agent-actions/run", req, {
    method: "POST",
    forwardQuery: false,
  });
}
