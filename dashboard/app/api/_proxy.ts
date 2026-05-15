const DASH_URL = process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";
const CORE_URL = process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";

export async function proxyLive(path: string, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const target = `${DASH_URL}/api/live/${path}${url.search}`;
  try {
    const upstream = await fetch(target);
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return Response.json({ ok: false, error: "upstream unreachable" }, { status: 503 });
  }
}

export { DASH_URL, CORE_URL };
