import { fetchCoreJson } from "../_proxy";
import {
  adaptHealth,
  type CoreAgentRecord,
  type CoreHealthResponse,
} from "../_adapters";

export async function GET(req: Request) {
  const [healthR, agentsR] = await Promise.all([
    fetchCoreJson<CoreHealthResponse>("health/detailed", "", req),
    fetchCoreJson<CoreAgentRecord[]>("agents", "", req),
  ]);

  if (!healthR.ok) return healthR.response;
  const agentCount = agentsR.ok ? agentsR.data.length : 0;

  return Response.json(adaptHealth(healthR.data, agentCount));
}
