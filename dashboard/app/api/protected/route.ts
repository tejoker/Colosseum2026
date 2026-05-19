import { fetchCoreJson } from "../_proxy";
import {
  adaptProtected,
  buildAgentNameMap,
  type CoreActionReceipt,
  type CoreAgentRecord,
} from "../_adapters";

export async function GET(req: Request) {
  const url = new URL(req.url);
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

  return Response.json(adaptProtected(receiptsR.data, buildAgentNameMap(agents)));
}
