import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

// Response security headers applied to every route. The dashboard renders
// operator audit logs, so framing/sniffing/referrer leakage are real risks.
// CSP is intentionally permissive enough for Next.js inline runtime styles
// while blocking framing and restricting connect/img/script origins to self.
const SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      // Next.js App Router injects inline hydration/RSC bootstrap scripts;
      // a strict script-src 'self' blocks them and the app never hydrates.
      // 'unsafe-inline' (+ 'unsafe-eval' for the client runtime) is the
      // pragmatic demo fix — production should use nonce-based CSP.
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "connect-src 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const config: NextConfig = {
  // Standalone output bundles a minimal server + only the needed node_modules
  // into .next/standalone, so the Docker runtime image stays small.
  output: "standalone",
  turbopack: {
    resolveAlias: {
      "next-intl/config": "./i18n/request.ts",
    },
  },
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
};

export default withNextIntl(config);
