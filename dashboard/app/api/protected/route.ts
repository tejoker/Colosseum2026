import { fetchCoreJson } from "../_proxy";
import {
  adaptProtected,
  buildAgentNameMap,
  type CoreEgressRow,
  type CoreAgentRecord,
} from "../_adapters";

// "Protected" = governance stops that really happened. We read blocked agent
// egress (allowed === false) from the core — the same real source the Activity
// → Stopped view uses — so every row is a rejection the core actually made.
export async function GET(req: Request) {
  const url = new URL(req.url);
  const limitRaw = url.searchParams.get("limit");
  const limit = limitRaw ? Math.max(1, Math.min(1000, Number(limitRaw))) : 1000;

  const [egressR, agentsR] = await Promise.all([
    fetchCoreJson<CoreEgressRow[]>("egress/recent", `?limit=${limit}`),
    fetchCoreJson<CoreAgentRecord[]>("agents"),
  ]);

  if (!egressR.ok) return egressR.response;
  const agents = agentsR.ok ? agentsR.data : [];

  return Response.json(adaptProtected(egressR.data, buildAgentNameMap(agents)));
}
