import { fetchCoreJson } from "../../../_proxy";
import {
  adaptAuditEvents,
  filterReceiptsByAgent,
  type CoreActionReceipt,
} from "../../../_adapters";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const url = new URL(req.url);
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");

  const r = await fetchCoreJson<CoreActionReceipt[]>(
    "agent_actions/recent",
    "?limit=1000"
  );
  if (!r.ok) return r.response;

  let rows = filterReceiptsByAgent(r.data, id);
  if (from) {
    const fromSec = Math.floor(new Date(from).getTime() / 1000);
    rows = rows.filter((x) => x.created_at >= fromSec);
  }
  if (to) {
    const toSec = Math.floor(new Date(to).getTime() / 1000);
    rows = rows.filter((x) => x.created_at <= toSec);
  }

  return Response.json(adaptAuditEvents(rows));
}
