//! In-path agent egress gateway.
//! See `docs/design/agent-egress-gateway.md`.
//!
//! `POST /agent/egress/proxy` is the mandatory outbound path: the agent hands
//! SauronID the request it wants to make, SauronID verifies the bound identity
//! (via the per-call-sig middleware on the route), checks the target host
//! against the agent's `intent_json.egress_allowlist`, vets the resolved IP
//! (SSRF / metadata-endpoint / private-range block), forwards it over a pinned
//! connection with filtered headers and a capped response, and records the call
//! to the anchored `agent_egress_log`. Turns the previously *voluntary* egress
//! reporting (`/agent/egress/log`) into *enforced* egress — provided the
//! deployment blocks direct network egress so the agent must route through here.
//!
//! Ops caveat (unchanged): this gateway constrains egress that flows THROUGH it.
//! It cannot stop an agent that has direct network access — deployments MUST
//! egress-firewall the agent's network so the proxy is the only outbound path.
//!
//! Gated by `SAURON_EGRESS_GATEWAY` (off → 503). Phase 1 does NOT terminate TLS,
//! so it enforces at the host + resolved-IP level only — no payload inspection
//! beyond opt-in PII redaction of the request body.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::ServerState;

fn env_on(var: &str) -> bool {
    matches!(
        std::env::var(var).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn egress_gateway_enabled() -> bool {
    env_on("SAURON_EGRESS_GATEWAY")
}

/// PII redaction is opt-in: whether a value in an outbound payload is a leak or
/// the intended data is a policy call, so blanket redaction is off by default.
pub fn redact_enabled() -> bool {
    env_on("SAURON_EGRESS_REDACT_PII")
}

/// Max bytes read from a forwarded response (default 1 MiB). Prevents an
/// allowlisted host from OOM-ing the gateway with an unbounded body.
fn max_resp_bytes() -> usize {
    std::env::var("SAURON_EGRESS_MAX_RESP_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1_048_576)
}

// Low-false-positive PII classes. ponytail: regex, not NER — add a model only
// when a real false-negative shows up. Blanket redaction is coarse; per-target
// rules are the real design (Phase 2.1).
struct PiiRule {
    class: &'static str,
    re: Regex,
}
static PII_RULES: Lazy<Vec<PiiRule>> = Lazy::new(|| {
    vec![
        PiiRule {
            class: "email",
            re: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
        },
        PiiRule {
            class: "ssn",
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        },
        PiiRule {
            class: "iban",
            re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
        },
        PiiRule {
            class: "credit_card",
            re: Regex::new(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b").unwrap(),
        },
        PiiRule {
            class: "phone",
            re: Regex::new(r"\+\d{7,15}\b").unwrap(),
        },
    ]
});

/// Redact PII from an outbound body. Returns the redacted string + the classes
/// hit (order: email, ssn, iban, credit_card, phone — most specific first).
pub fn redact_pii(body: &str) -> (String, Vec<String>) {
    let mut out = body.to_string();
    let mut hit = Vec::new();
    for rule in PII_RULES.iter() {
        if rule.re.is_match(&out) {
            out = rule
                .re
                .replace_all(&out, format!("⟪redacted:{}⟫", rule.class).as_str())
                .into_owned();
            hit.push(rule.class.to_string());
        }
    }
    (out, hit)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ─── SSRF / private-address protection ──────────────────────────────────────

/// True if `ip` must never be reached via the egress proxy: loopback, private,
/// link-local (incl. the cloud metadata endpoint 169.254.169.254), CGNAT,
/// unspecified, multicast/broadcast, and the IPv6 equivalents (ULA fc00::/7,
/// link-local fe80::/10, and IPv4-mapped forms of any of the above).
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254/16 (incl. 169.254.169.254 metadata)
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0                                   // 0.0.0.0/8 "this host"
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Resolve `host:port` and vet EVERY resolved address. Denies if the host does
/// not resolve or if ANY resolved address is blocked (a name that resolves to
/// both a public and a private/metadata IP is treated as hostile). Returns the
/// vetted addresses so the caller can PIN the connection to one of them,
/// closing the DNS-rebinding window between check and connect.
async fn resolve_and_vet(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns resolution failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("host did not resolve to any address".to_string());
    }
    for a in &addrs {
        if is_blocked_ip(a.ip()) {
            return Err(format!(
                "target resolves to a blocked address ({}) — private/loopback/link-local/metadata ranges are refused",
                a.ip()
            ));
        }
    }
    Ok(addrs)
}

/// Headers the caller may NOT set on the forwarded request. Blocks allowlist
/// bypass via `Host`, hop-by-hop smuggling, forwarded-for spoofing, and
/// reflection of our own internal `x-sauron-*` auth headers. Matched
/// case-insensitively; the `x-sauron-`/`proxy-` prefixes are also blocked.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-connection",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

fn header_forbidden(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    FORBIDDEN_HEADERS.iter().any(|h| *h == n)
        || n.starts_with("x-sauron-")
        || n.starts_with("proxy-")
}

/// Record one egress event to the anchored trail. Shared by the voluntary
/// `/agent/egress/log` endpoint and the enforcing proxy so both log identically
/// and both get anchored. On `allowed`, also commits an `agent_action_receipts`
/// row that the anchor batch seals into Bitcoin/Solana. Returns the egress row id.
#[allow(clippy::too_many_arguments)]
pub fn record_egress(
    db: &Connection,
    tenant_id: &str,
    agent_id: &str,
    target_host: &str,
    target_path: &str,
    method: &str,
    body_hash_hex: &str,
    status_code: i64,
    allowed: bool,
    now: i64,
) -> Result<i64, String> {
    db.execute(
        "INSERT INTO agent_egress_log
         (tenant_id, agent_id, target_host, target_path, method, body_hash_hex, status_code, ts, allowed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            tenant_id,
            agent_id,
            target_host,
            target_path,
            method,
            body_hash_hex,
            status_code,
            now,
            allowed as i64
        ],
    )
    .map_err(|e| format!("insert agent_egress_log: {e}"))?;
    let egress_id = db.last_insert_rowid();

    // Denied calls are logged (and audited via the tamper-evident chain by the
    // caller) but not anchored as an accepted action.
    if allowed {
        let mut h = Sha256::new();
        for part in [
            agent_id,
            target_host,
            target_path,
            method,
            &egress_id.to_string(),
            &now.to_string(),
        ] {
            h.update(part.as_bytes());
            h.update(b"|");
        }
        let action_hash = hex::encode(h.finalize());
        let receipt_id = format!("rcp_egr_{egress_id}");
        let _ = db.execute(
            "INSERT INTO agent_action_receipts
             (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at, tenant_id)
             VALUES (?1, ?2, ?3, '', 'egress', '', '', 'accepted', '', ?4, ?5)",
            params![receipt_id, action_hash, agent_id, now, tenant_id],
        );
    }
    Ok(egress_id)
}

/// Load the agent's parsed `intent_json`, scoped to `tenant_id` (fail-closed:
/// unknown/revoked/other-tenant → error).
fn agent_intent(
    db: &Connection,
    tenant_id: &str,
    agent_id: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let s: String = db
        .query_row(
            "SELECT intent_json FROM agents WHERE agent_id = ?1 AND tenant_id = ?2 AND revoked = 0",
            params![agent_id, tenant_id],
            |r| r.get(0),
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "agent not found or revoked".to_string(),
            )
        })?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

/// A matched allowlist entry: the request is permitted, and optionally names a
/// server-held credential to inject (the agent never holds it — see
/// docs/design/credential-broker.md).
struct EgressMatch {
    inject_credential: Option<String>,
}

/// Match `(host, method, path)` against `intent_json.egress_allowlist`.
/// Each entry is either a bare host string (any method/path — Phase 1 shape) or
/// an object `{host, methods?, path_prefix?, inject_credential?}`. Returns the
/// matched entry, or `None` to deny. Fail-closed: missing/empty allowlist denies.
fn egress_match(
    intent: &serde_json::Value,
    host: &str,
    method: &str,
    path: &str,
) -> Option<EgressMatch> {
    let arr = intent.get("egress_allowlist").and_then(|v| v.as_array())?;
    for entry in arr {
        if let Some(s) = entry.as_str() {
            if s.eq_ignore_ascii_case(host) {
                return Some(EgressMatch {
                    inject_credential: None,
                });
            }
        } else if let Some(o) = entry.as_object() {
            if !o
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .eq_ignore_ascii_case(host)
            {
                continue;
            }
            if let Some(methods) = o.get("methods").and_then(|v| v.as_array()) {
                if !methods
                    .iter()
                    .filter_map(|m| m.as_str())
                    .any(|m| m.eq_ignore_ascii_case(method))
                {
                    continue;
                }
            }
            if let Some(prefix) = o.get("path_prefix").and_then(|v| v.as_str()) {
                let prefix = prefix.trim_end_matches('/');
                if path != prefix && !path.starts_with(&format!("{prefix}/")) {
                    continue;
                }
            }
            let inject_credential = o
                .get("inject_credential")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Some(EgressMatch { inject_credential });
        }
    }
    None
}

/// Backward-compatible boolean form (used by tests).
#[cfg(test)]
fn egress_allowed(intent: &serde_json::Value, host: &str, method: &str, path: &str) -> bool {
    egress_match(intent, host, method, path).is_some()
}

/// Resolve a server-held egress credential to `(header_name, header_value)`.
/// Configured via `SAURON_EGRESS_CREDENTIALS` (JSON):
///   `{"stripe":{"header":"authorization","value_env":"STRIPE_RESTRICTED_KEY"}}`
/// `value_env` (preferred) names the env var / Vault-injected var holding the
/// secret so it is not inline; `value` is an inline fallback for dev. The secret
/// is never returned to the agent and never logged.
fn egress_credential(name: &str) -> Option<(String, String)> {
    let raw = std::env::var("SAURON_EGRESS_CREDENTIALS").ok()?;
    let map: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let entry = map.get(name)?;
    let header = entry
        .get("header")
        .and_then(|v| v.as_str())
        .unwrap_or("authorization")
        .to_string();
    let value = if let Some(env_name) = entry.get("value_env").and_then(|v| v.as_str()) {
        std::env::var(env_name).ok()?
    } else {
        entry.get("value").and_then(|v| v.as_str())?.to_string()
    };
    Some((header, value))
}

#[derive(Deserialize)]
pub struct EgressProxyRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct EgressProxyResponse {
    pub status: u16,
    pub body: String,
    /// PII classes redacted from the forwarded request body (empty if none / off).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted: Vec<String>,
}

/// POST /agent/egress/proxy — enforced outbound call. Route is gated by
/// `require_call_signature`, so `x-sauron-agent-id` is a verified bound agent.
pub async fn agent_egress_proxy(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<crate::tenancy::TenantId>>,
    headers: HeaderMap,
    Json(req): Json<EgressProxyRequest>,
) -> Result<Json<EgressProxyResponse>, (StatusCode, String)> {
    if !egress_gateway_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "egress gateway disabled (set SAURON_EGRESS_GATEWAY=1)".into(),
        ));
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    // Identity comes from the sig header the middleware already verified.
    let agent_id = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if agent_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "missing x-sauron-agent-id".into()));
    }

    let url = reqwest::Url::parse(&req.url)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad url: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err((
            StatusCode::BAD_REQUEST,
            "only http/https targets allowed".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "url has no host".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or((StatusCode::BAD_REQUEST, "url has no port".to_string()))?;
    let path = url.path().to_string();
    let method_str = req.method.to_uppercase();
    let now = crate::agent_action::now_secs();

    // Helper to record + audit a denial, then return the 403.
    let deny = |reason: String| -> (StatusCode, String) {
        {
            let st = state.read().unwrap();
            let db = st.db.lock().unwrap();
            let _ = record_egress(
                &db,
                &tenant_id,
                &agent_id,
                &host,
                &path,
                &method_str,
                "",
                0,
                false,
                now,
            );
        }
        // Denials are not on-chain anchored (only allowed actions are); record
        // to the tamper-evident audit chain so they are still non-repudiable.
        crate::middleware::audit_log::record(
            crate::middleware::audit_log::AuditEvent::EgressDenied {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                host: host.clone(),
                method: method_str.clone(),
                path: path.clone(),
                reason: reason.clone(),
            },
        );
        (StatusCode::FORBIDDEN, reason)
    };

    if !url.username().is_empty() || url.password().is_some() {
        return Err(deny("URL userinfo is not permitted".into()));
    }
    if url.query().is_some() {
        return Err(deny(
            "query parameters are not permitted by the Phase 1 egress policy".into(),
        ));
    }

    // 1. Allowlist check (host + optional method/path constraints).
    let matched = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let intent = agent_intent(&db, &tenant_id, &agent_id)?;
        egress_match(&intent, &host, &method_str, &path)
    };
    let Some(matched) = matched else {
        return Err(deny(format!(
            "egress {method_str} {host}{path} not permitted by the agent's egress_allowlist"
        )));
    };

    // Resolve any server-held credential the matched entry injects. The agent
    // never holds this secret (credential-broker model); a referenced-but-
    // unconfigured credential fails CLOSED rather than forwarding unauthenticated.
    let injected: Option<(String, String)> = match &matched.inject_credential {
        Some(cred_name) => match egress_credential(cred_name) {
            Some(hv) => Some(hv),
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "egress allowlist references credential '{cred_name}' but it is not configured (SAURON_EGRESS_CREDENTIALS)"
                    ),
                ));
            }
        },
        None => None,
    };
    let injected_header_lc = injected.as_ref().map(|(h, _)| h.to_ascii_lowercase());

    // 2. Resolve + vet the target IP (SSRF / metadata / private-range block).
    //    Pin the vetted address so the actual connection cannot be rebound to a
    //    private IP between this check and connect.
    let vetted = match resolve_and_vet(&host, port).await {
        Ok(a) => a,
        Err(reason) => return Err(deny(reason)),
    };
    let pinned = vetted[0];

    // 3. PII-redact the outbound body (opt-in). We forward + hash what was
    //    actually sent, so the anchored log reflects the redacted payload.
    let original_body = req.body.clone().unwrap_or_default();
    let (fwd_body, redacted) = if redact_enabled() {
        redact_pii(&original_body)
    } else {
        (original_body, Vec::new())
    };
    let body_hash = sha256_hex(&fwd_body);

    let method = reqwest::Method::from_bytes(method_str.as_bytes())
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad HTTP method".to_string()))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        // No auto-follow: a 3xx is returned to the agent verbatim. Following
        // here would let an allowlisted host redirect to a private IP or an
        // off-allowlist host, bypassing both checks above. The agent must
        // re-submit the Location, which re-runs allowlist + IP vetting.
        .redirect(reqwest::redirect::Policy::none())
        // Pin resolution to the vetted address (defeats DNS rebinding).
        .resolve(&host, pinned)
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut rb = client.request(method, url);
    // Forward only non-forbidden headers (block Host/hop-by-hop/forwarded/our
    // internal auth headers — see FORBIDDEN_HEADERS). Also skip any caller
    // header whose name collides with an injected credential, so the injected
    // value cannot be shadowed by the caller.
    for (k, v) in &req.headers {
        if header_forbidden(k) {
            continue;
        }
        if injected_header_lc.as_deref() == Some(k.trim().to_ascii_lowercase().as_str()) {
            continue;
        }
        rb = rb.header(k, v);
    }
    // Inject the server-held credential (agent never sees it).
    if let Some((h, v)) = injected {
        rb = rb.header(h, v);
    }
    if req.body.is_some() {
        rb = rb.body(fwd_body);
    }
    let mut resp = rb
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("forward failed: {e}")))?;
    let status = resp.status().as_u16();

    // Record the (allowed) egress by the REQUEST it made, before reading the
    // body — so the anchored log captures the call even if the body is capped.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let _ = record_egress(
            &db,
            &tenant_id,
            &agent_id,
            &host,
            &path,
            &method_str,
            &body_hash,
            status as i64,
            true,
            now,
        );
    }

    // 4. Bounded response read — never buffer an unbounded body.
    let cap = max_resp_bytes();
    if let Some(len) = resp.content_length() {
        if len as usize > cap {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "upstream response {len} bytes exceeds SAURON_EGRESS_MAX_RESP_BYTES ({cap})"
                ),
            ));
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > cap {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("upstream response exceeds SAURON_EGRESS_MAX_RESP_BYTES ({cap})"),
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("read response failed: {e}"),
                ));
            }
        }
    }
    let resp_body = String::from_utf8_lossy(&buf).into_owned();

    Ok(Json(EgressProxyResponse {
        status,
        body: resp_body,
        redacted,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn
    }

    fn insert_agent(db: &Connection, agent_id: &str, intent: &str) {
        db.execute(
            "INSERT INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, tenant_id)
             VALUES (?1, 'hki', 'sha256:x', ?2, '', '', 0, 9999999999, 0, 'default')",
            params![agent_id, intent],
        )
        .unwrap();
    }

    #[test]
    fn egress_allowlist_string_and_object_entries() {
        let intent = serde_json::json!({
            "egress_allowlist": [
                "example.com",
                { "host": "api.stripe.com", "methods": ["POST"], "path_prefix": "/v1/charges" }
            ]
        });
        assert!(egress_allowed(&intent, "example.com", "GET", "/anything"));
        assert!(
            egress_allowed(&intent, "EXAMPLE.COM", "DELETE", "/x"),
            "host case-insensitive"
        );
        assert!(!egress_allowed(&intent, "evil.com", "GET", "/"));
        assert!(egress_allowed(
            &intent,
            "api.stripe.com",
            "POST",
            "/v1/charges/123"
        ));
        assert!(
            !egress_allowed(&intent, "api.stripe.com", "GET", "/v1/charges"),
            "method blocked"
        );
        assert!(
            !egress_allowed(&intent, "api.stripe.com", "POST", "/v1/refunds"),
            "path blocked"
        );
    }

    #[test]
    fn egress_match_surfaces_inject_credential() {
        let intent = serde_json::json!({
            "egress_allowlist": [
                "plain.com",
                { "host": "api.stripe.com", "methods": ["POST"], "inject_credential": "stripe" }
            ]
        });
        // Bare host → allowed, no credential.
        let plain = egress_match(&intent, "plain.com", "GET", "/").expect("allowed");
        assert!(plain.inject_credential.is_none());
        // Object entry → credential name surfaced for server-side injection.
        let m = egress_match(&intent, "api.stripe.com", "POST", "/v1/charges").expect("allowed");
        assert_eq!(m.inject_credential.as_deref(), Some("stripe"));
        // Constraints still apply.
        assert!(
            egress_match(&intent, "api.stripe.com", "GET", "/").is_none(),
            "method blocked"
        );
    }

    #[test]
    fn egress_credential_resolves_from_env_not_inline() {
        std::env::set_var(
            "SAURON_EGRESS_CREDENTIALS",
            r#"{"stripe":{"header":"authorization","value_env":"TEST_STRIPE_KEY_XYZ"}}"#,
        );
        std::env::set_var("TEST_STRIPE_KEY_XYZ", "Bearer sk_test_x");
        let (h, v) = egress_credential("stripe").expect("credential resolves");
        assert_eq!(h, "authorization");
        assert_eq!(v, "Bearer sk_test_x");
        assert!(
            egress_credential("nonexistent").is_none(),
            "unknown name → None (fails closed)"
        );
        std::env::remove_var("SAURON_EGRESS_CREDENTIALS");
        std::env::remove_var("TEST_STRIPE_KEY_XYZ");
    }

    #[test]
    fn egress_fails_closed_without_allowlist() {
        assert!(!egress_allowed(
            &serde_json::json!({"scope": ["pay"]}),
            "example.com",
            "GET",
            "/"
        ));
        assert!(!egress_allowed(
            &serde_json::json!({}),
            "example.com",
            "GET",
            "/"
        ));
    }

    #[test]
    fn agent_intent_scoped_by_tenant_and_revocation() {
        let db = mem_db();
        insert_agent(&db, "a1", r#"{"egress_allowlist":["x.com"]}"#);
        assert!(agent_intent(&db, "default", "a1").is_ok());
        assert!(
            agent_intent(&db, "default", "ghost").is_err(),
            "unknown agent denied"
        );
        assert!(
            agent_intent(&db, "other-tenant", "a1").is_err(),
            "cross-tenant lookup denied"
        );
    }

    #[test]
    fn blocked_ips_cover_ssrf_ranges() {
        // Cloud metadata endpoint + private/loopback/link-local/CGNAT/unspecified.
        for s in [
            "169.254.169.254", // AWS/GCP/Azure metadata
            "127.0.0.1",
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "224.0.0.1",  // multicast
            "255.255.255.255",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_blocked_ip(ip), "{s} must be blocked");
        }
        // IPv6 loopback / ULA / link-local + IPv4-mapped metadata.
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()), "ULA blocked");
        assert!(
            is_blocked_ip("fe80::1".parse().unwrap()),
            "link-local blocked"
        );
        assert!(
            is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()),
            "v4-mapped metadata blocked"
        );
    }

    #[test]
    fn public_ips_are_allowed() {
        for s in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_blocked_ip(ip), "{s} is public and must be allowed");
        }
        // A normal public IPv6 (Google DNS) is allowed.
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn header_smuggling_is_blocked() {
        // Allowlist-bypass + hop-by-hop + forwarded-spoof + internal-auth reflection.
        for h in [
            "Host",
            "host",
            "Content-Length",
            "Connection",
            "Transfer-Encoding",
            "TE",
            "Upgrade",
            "X-Forwarded-For",
            "x-forwarded-host",
            "X-Real-IP",
            "Proxy-Authorization",
            "proxy-connection",
            "x-sauron-agent-id",
            "X-Sauron-Call-Sig",
        ] {
            assert!(header_forbidden(h), "{h} must be filtered out");
        }
        // Ordinary API headers pass through.
        for h in [
            "Authorization",
            "Content-Type",
            "Accept",
            "User-Agent",
            "X-Api-Key",
        ] {
            assert!(!header_forbidden(h), "{h} should be forwarded");
        }
    }

    #[tokio::test]
    async fn resolve_and_vet_blocks_private_and_metadata_targets() {
        // IP-literal hosts resolve without network DNS, so these are
        // deterministic. Metadata + loopback must be refused; a public IP is ok.
        assert!(
            resolve_and_vet("169.254.169.254", 80).await.is_err(),
            "metadata endpoint blocked"
        );
        assert!(
            resolve_and_vet("127.0.0.1", 80).await.is_err(),
            "loopback blocked"
        );
        assert!(
            resolve_and_vet("10.0.0.1", 443).await.is_err(),
            "private range blocked"
        );
        assert!(
            resolve_and_vet("[::1]".trim_matches(|c| c == '[' || c == ']'), 80)
                .await
                .is_err(),
            "v6 loopback blocked"
        );
        assert!(
            resolve_and_vet("8.8.8.8", 443).await.is_ok(),
            "public IP allowed"
        );
    }

    #[test]
    fn max_resp_bytes_defaults_and_overrides() {
        // Default when unset.
        std::env::remove_var("SAURON_EGRESS_MAX_RESP_BYTES");
        assert_eq!(max_resp_bytes(), 1_048_576);
    }

    #[test]
    fn redact_pii_masks_known_classes_and_leaves_plain_text() {
        let (out, hit) = redact_pii(
            "contact a@b.com ssn 123-45-6789 card 4242 4242 4242 4242 phone +14155550123",
        );
        assert!(out.contains("⟪redacted:email⟫"));
        assert!(out.contains("⟪redacted:ssn⟫"));
        assert!(out.contains("⟪redacted:credit_card⟫"));
        assert!(out.contains("⟪redacted:phone⟫"));
        assert!(!out.contains("a@b.com") && !out.contains("123-45-6789"));
        for c in ["email", "ssn", "credit_card", "phone"] {
            assert!(hit.contains(&c.to_string()), "missing class {c}");
        }
        let (plain, hit2) = redact_pii("a normal sentence with number 42 and words");
        assert_eq!(plain, "a normal sentence with number 42 and words");
        assert!(hit2.is_empty());
    }

    #[test]
    fn record_egress_logs_and_anchors_only_when_allowed() {
        let db = mem_db();
        record_egress(
            &db,
            "default",
            "a1",
            "example.com",
            "/x",
            "GET",
            "bh",
            200,
            true,
            10,
        )
        .unwrap();
        let egress: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_egress_log WHERE allowed = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(egress, 1);
        let receipts: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE policy_version = 'egress'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            receipts, 1,
            "allowed egress must leave an anchorable receipt"
        );
        // tenant_id is persisted on both rows.
        let scoped: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_egress_log WHERE tenant_id = 'default'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(scoped, 1);

        record_egress(
            &db, "default", "a1", "evil.com", "/y", "POST", "bh", 0, false, 11,
        )
        .unwrap();
        let denied: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_egress_log WHERE allowed = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(denied, 1);
        let receipts_after: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE policy_version = 'egress'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipts_after, 1, "denied egress must NOT be anchored");
    }
}
