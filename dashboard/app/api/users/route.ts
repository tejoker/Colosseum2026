import { fetchCoreJson } from "../_proxy";
import { adaptPeople, type CoreUserRecord } from "../_adapters";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const companyId = url.searchParams.get("company_id");

  const r = await fetchCoreJson<CoreUserRecord[]>("users");
  if (!r.ok) return r.response;

  let people = adaptPeople(r.data);
  if (companyId) {
    // The /admin/users endpoint does not carry per-company linkage in its current
    // shape — return an empty list rather than mis-attributing users to a client.
    people = people.filter((p) => p.company_id === companyId);
  }
  return Response.json(people);
}
