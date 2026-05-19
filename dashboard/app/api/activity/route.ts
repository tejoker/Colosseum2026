import { fetchCoreJson } from "../_proxy";
import {
  adaptActivity,
  buildAgentNameMap,
  filterReceiptsByAgent,
  filterReceiptsByResult,
  type CoreActionReceipt,
  type CoreAgentRecord,
} from "../_adapters";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const agentId = url.searchParams.get("agent_id");
  const result = url.searchParams.get("result") as "allowed" | "stopped" | null;
  const limitRaw = url.searchParams.get("limit");
  const limit = limitRaw ? Math.max(1, Math.min(1000, Number(limitRaw))) : 200;

  const [receiptsR, agentsR] = await Promise.all([
    fetchCoreJson<CoreActionReceipt[]>(
      "agent_actions/recent",
      `?limit=${limit}`
    ),
    fetchCoreJson<CoreAgentRecord[]>("agents"),
  ]);

  if (!receiptsR.ok) return receiptsR.response;
  const agents = agentsR.ok ? agentsR.data : [];

  let rows = receiptsR.data;
  rows = filterReceiptsByAgent(rows, agentId);
  rows = filterReceiptsByResult(rows, result);

  return Response.json(adaptActivity(rows, buildAgentNameMap(agents)));
}
