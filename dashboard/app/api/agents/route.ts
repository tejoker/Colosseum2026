import { fetchCoreJson } from "../_proxy";
import {
  adaptAgents,
  type CoreAgentRecord,
  type CorePerAgentMetric,
} from "../_adapters";

export async function GET(_req: Request) {
  const [agentsR, metricsR] = await Promise.all([
    fetchCoreJson<CoreAgentRecord[]>("agents"),
    fetchCoreJson<CorePerAgentMetric[]>("per_agent_metrics", "?limit=500"),
  ]);

  if (!agentsR.ok) return agentsR.response;
  const metrics = metricsR.ok ? metricsR.data : [];

  return Response.json(adaptAgents(agentsR.data, metrics));
}
