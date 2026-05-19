import { fetchCoreJson } from "../../_proxy";
import { adaptCompanies, type CoreClientRecord } from "../../_adapters";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const r = await fetchCoreJson<CoreClientRecord[]>("clients");
  if (!r.ok) return r.response;

  const all = adaptCompanies(r.data);
  const one = all.find((c) => c.id === id || c.name === id);
  if (!one) {
    return Response.json({ ok: false, error: "Client not found" }, { status: 404 });
  }
  return Response.json(one);
}
