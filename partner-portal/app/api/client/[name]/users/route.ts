import { fetchAdminJson } from "../../../_adminProxy";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ name: string }> }
) {
  const { name } = await params;
  return fetchAdminJson(req, `/admin/site/${encodeURIComponent(name)}/users`);
}
