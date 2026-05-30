//! Response security-headers middleware.
//!
//! SauronID serves a governance/audit API and (next to it) an admin
//! dashboard. CORS is already locked down in `main.rs`; this layer adds the
//! complementary response hardening headers that browsers honour:
//!
//! - `X-Content-Type-Options: nosniff` — no MIME sniffing.
//! - `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`
//!   — clickjacking / framing defence (belt-and-braces; CSP supersedes XFO on
//!   modern browsers but XFO covers older ones).
//! - `Content-Security-Policy: default-src 'none'` — this is a JSON API; no
//!   document resources should ever load. The dashboard ships its own CSP via
//!   Next.js, so this only constrains the core API responses.
//! - `Referrer-Policy: no-referrer` — never leak URLs cross-origin.
//! - `Strict-Transport-Security` — force HTTPS for two years incl. subdomains.
//!   Harmless over plain HTTP (browsers ignore it); meaningful once a TLS proxy
//!   terminates in front of the service.
//!
//! Headers are only inserted when absent so a handler that sets a deliberate
//! per-response policy (e.g. a future docs page) is never clobbered.

use axum::extract::Request;
use axum::http::header::{
    HeaderValue, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

const HSTS: &str = "max-age=63072000; includeSubDomains";
const CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// Tower middleware that stamps security headers on every response.
pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    let defaults: [(_, HeaderValue); 5] = [
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
        (CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)),
        (STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS)),
    ];
    for (name, value) in defaults {
        if !headers.contains_key(&name) {
            headers.insert(name, value);
        }
    }
    resp
}
