import { fetchCoreJson } from "../_proxy";
import { adaptCompanies, type CoreClientRecord } from "../_adapters";

export async function GET(req: Request) {
  const r = await fetchCoreJson<CoreClientRecord[]>("clients", "", req);
  if (!r.ok) return r.response;
  return Response.json(adaptCompanies(r.data));
}
