// Same-origin proxy for `/v1/policy/list` (GET) and `/v1/policy/upload` (POST).
// Admin auth injected by the proxy helper. The browser never sees the core URL
// or the admin key.

import { NextRequest } from "next/server";
import { fetchCoreV1Json, proxyCoreV1 } from "../_proxy";
import type { PolicySummary } from "@/lib/api";

export async function GET(_req: Request) {
  const r = await fetchCoreV1Json<PolicySummary[]>("policy/list");
  if (!r.ok) return r.response;
  return Response.json(r.data);
}

export async function POST(req: NextRequest) {
  const contentType = req.headers.get("content-type") ?? "application/json";
  const body = await req.text();
  return proxyCoreV1("policy/upload", req, {
    method: "POST",
    body,
    extraHeaders: { "content-type": contentType },
  });
}
