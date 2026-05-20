// Next.js middleware (Sprint 11.6).
//
// Purpose: copy the `sauron_tenant_id` cookie onto an `x-sauron-tenant-id`
// request header on every same-origin navigation + `/api/*` call so that
// Server Components, route handlers, and downstream proxies all see the
// active tenant without having to read the cookie themselves.
//
// Scope: applies to `/api/*` (where the proxy reads the header) and to the
// page routes (where Server Components might want to read it via
// `headers()`). Skips `_next/*`, static assets, and the public health
// surface — none of those are tenant-scoped.

import { NextRequest, NextResponse } from "next/server";

const TENANT_COOKIE = "sauron_tenant_id";
const TENANT_HEADER = "x-sauron-tenant-id";

export function middleware(req: NextRequest) {
  const cookieValue = req.cookies.get(TENANT_COOKIE)?.value?.trim();
  // If the request already carries the header (e.g. set explicitly by
  // browser-side `lib/api.ts`) we leave it alone so the client always wins.
  const hasHeader = req.headers.get(TENANT_HEADER);
  if (!cookieValue || hasHeader) {
    return NextResponse.next();
  }
  // Forward as a new request header for the downstream handler.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set(TENANT_HEADER, cookieValue);
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: [
    // Apply to API routes + page routes, skip Next.js internals + static.
    "/((?!_next/static|_next/image|favicon.ico|logo.svg).*)",
  ],
};
