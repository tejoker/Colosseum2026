import { fetchAdminJson } from "../_adminProxy";

export async function GET(req: Request) {
  return fetchAdminJson(req, "/admin/clients");
}
