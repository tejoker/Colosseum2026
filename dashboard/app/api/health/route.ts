import { fetchCoreJson } from "../_proxy";
import {
  adaptHealth,
  type CoreAgentRecord,
  type CoreHealthResponse,
} from "../_adapters";

export async function GET(_req: Request) {
  const [healthR, agentsR] = await Promise.all([
    fetchCoreJson<CoreHealthResponse>("health/detailed"),
    fetchCoreJson<CoreAgentRecord[]>("agents"),
  ]);

  if (!healthR.ok) return healthR.response;
  const agentCount = agentsR.ok ? agentsR.data.length : 0;

  return Response.json(adaptHealth(healthR.data, agentCount));
}
