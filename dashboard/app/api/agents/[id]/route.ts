import { fetchCoreJson } from "../../_proxy";
import {
  adaptAgent,
  type CoreAgentRecord,
  type CorePerAgentMetric,
} from "../../_adapters";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const [agentsR, metricsR] = await Promise.all([
    fetchCoreJson<CoreAgentRecord[]>("agents"),
    fetchCoreJson<CorePerAgentMetric[]>("per_agent_metrics", "?limit=500"),
  ]);

  if (!agentsR.ok) return agentsR.response;
  const metrics = metricsR.ok ? metricsR.data : [];
  const m = new Map(metrics.map((x) => [x.agent_id, x] as const));

  const row = agentsR.data.find((a) => a.agent_id === id);
  if (!row) {
    return Response.json({ ok: false, error: "Agent not found" }, { status: 404 });
  }
  return Response.json(adaptAgent(row, m));
}
