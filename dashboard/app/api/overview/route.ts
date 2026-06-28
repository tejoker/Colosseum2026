import { fetchCoreJson } from "../_proxy";
import {
  adaptOverview,
  type CoreEgressRow,
  type CoreAgentRecord,
} from "../_adapters";

// Home counters derive from REAL agent egress (same source as Activity), so
// "calls today" / "protected today" reflect what the agents actually did and
// what the core actually rejected — not receipt-status guesswork.
export async function GET(_req: Request) {
  const [agentsR, egressR] = await Promise.all([
    fetchCoreJson<CoreAgentRecord[]>("agents"),
    fetchCoreJson<CoreEgressRow[]>("egress/recent", "?limit=1000"),
  ]);

  if (!agentsR.ok) return agentsR.response;
  const egress = egressR.ok ? egressR.data : [];

  return Response.json(adaptOverview(agentsR.data, egress));
}
