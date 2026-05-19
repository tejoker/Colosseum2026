import { fetchCoreJson } from "../_proxy";
import {
  adaptOverview,
  type CoreActionReceipt,
  type CoreAgentRecord,
} from "../_adapters";

export async function GET(_req: Request) {
  const [agentsR, receiptsR] = await Promise.all([
    fetchCoreJson<CoreAgentRecord[]>("agents"),
    fetchCoreJson<CoreActionReceipt[]>("agent_actions/recent", "?limit=1000"),
  ]);

  if (!agentsR.ok) return agentsR.response;
  const receipts = receiptsR.ok ? receiptsR.data : [];

  return Response.json(adaptOverview(agentsR.data, receipts));
}
