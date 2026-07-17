import { fetchCoreJson } from "../_proxy";
import {
  adaptOverview,
  type CoreEgressRow,
  type CoreAgentRecord,
} from "../_adapters";

// Home counters derive from REAL agent egress (same source as Activity), so
// "calls today" / "protected today" reflect what the agents actually did and
// what the core actually rejected — not receipt-status guesswork.
export async function GET(req: Request) {
  const [agentsR, egressR] = await Promise.all([
    fetchCoreJson<CoreAgentRecord[]>("agents", "", req),
    fetchCoreJson<CoreEgressRow[]>("egress/recent", "?limit=1000", req),
  ]);

  if (!agentsR.ok) return agentsR.response;
  const egress = egressR.ok ? egressR.data : [];

  return Response.json(adaptOverview(agentsR.data, egress));
}
