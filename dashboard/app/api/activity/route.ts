import { fetchCoreJson } from "../_proxy";
import {
  adaptEgress,
  buildAgentNameMap,
  type CoreEgressRow,
  type CoreAgentRecord,
} from "../_adapters";

// Live monitor: the REAL outbound calls every agent made (the LLM calls + tool
// fetches), straight from the core's egress log. This reflects the actual
// agents you run from the Console, not a simulation.
export async function GET(req: Request) {
  const url = new URL(req.url);
  const agentId = url.searchParams.get("agent_id");
  const result = url.searchParams.get("result") as "allowed" | "stopped" | null;
  const limitRaw = url.searchParams.get("limit");
  const limit = limitRaw ? Math.max(1, Math.min(1000, Number(limitRaw))) : 200;

  const [egressR, agentsR] = await Promise.all([
    fetchCoreJson<CoreEgressRow[]>("egress/recent", `?limit=${limit}`, req),
    fetchCoreJson<CoreAgentRecord[]>("agents", "", req),
  ]);

  if (!egressR.ok) return egressR.response;
  const agents = agentsR.ok ? agentsR.data : [];

  let rows = adaptEgress(egressR.data, buildAgentNameMap(agents));
  if (agentId) rows = rows.filter((r) => r.agent_id === agentId);
  if (result === "allowed" || result === "stopped") {
    rows = rows.filter((r) => r.result === result);
  }
  return Response.json(rows);
}
