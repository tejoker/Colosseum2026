import { fetchCoreJson } from "../_proxy";
import { adaptAnchorStats, type CoreAnchorStatus } from "../_adapters";

export async function GET(_req: Request) {
  const r = await fetchCoreJson<CoreAnchorStatus>("anchor/status");
  if (!r.ok) return r.response;
  return Response.json(adaptAnchorStats(r.data));
}
