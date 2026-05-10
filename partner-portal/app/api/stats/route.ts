import { fetchAdminJson } from "../_adminProxy";

/**
 * Server-side proxy for /admin/stats.
 * The SAURON_ADMIN_KEY secret never reaches the browser.
 */
export async function GET(req: Request) {
  return fetchAdminJson(req, "/admin/stats", { next: { revalidate: 5 } });
}
