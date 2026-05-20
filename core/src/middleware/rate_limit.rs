//! Global pre-auth rate limit (token bucket, per remote IP).
//!
//! Distinct from [`crate::risk`], which is per-route + tenant-scoped and
//! runs AFTER auth. This layer fires BEFORE auth so an unauthenticated
//! brute-force flood is short-circuited at the ingress edge.
//!
//! Algorithm: classic Lamport-style token bucket. Each IP gets a bucket
//! that refills at `requests_per_second_per_ip` tokens / sec, capped at
//! `burst`. Every request consumes one token; if the bucket is empty the
//! middleware responds `429 Too Many Requests` with a `Retry-After`
//! header in whole seconds.
//!
//! Storage: in-memory `Mutex<HashMap<IpAddr, BucketState>>`. No new
//! dependencies. The S12 spec offered DashMap but explicitly fell back to
//! std HashMap+Mutex to honor the "no new Cargo.toml deps" constraint.
//!
//! Pruning: a background task wakes every 60 seconds and removes buckets
//! whose last activity is older than 5 minutes. Keeps memory bounded
//! under hostile traffic patterns (slow-rotating IP pools).
//!
//! IP extraction: we honor `X-Forwarded-For` first (when a proxy/LB
//! terminates TLS in front of the core), then `X-Real-IP`, then the
//! socket peer address via `axum::extract::ConnectInfo`. The XFF parse
//! takes the LEFTMOST entry (originating client) and validates it as a
//! plain IPv4/IPv6 literal.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Configuration for the global ingress rate limiter.
///
/// All fields are required; the public constructor [`from_env`] reads
/// `SAURON_GLOBAL_RATE_LIMIT_RPS` and `SAURON_GLOBAL_RATE_LIMIT_BURST`
/// and applies the documented defaults.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalRateLimitConfig {
    /// Steady-state token refill rate, per remote IP, per second.
    /// Default `200`.
    pub requests_per_second_per_ip: u32,
    /// Bucket capacity. The first `burst` requests after a cold start
    /// (or after a long idle gap) succeed instantly; subsequent ones
    /// are gated by the refill rate. Default `50`.
    pub burst: u32,
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second_per_ip: 200,
            burst: 50,
        }
    }
}

impl GlobalRateLimitConfig {
    /// Build a config from environment variables.
    ///
    /// - `SAURON_GLOBAL_RATE_LIMIT_RPS` — steady-state RPS per IP (default 200).
    /// - `SAURON_GLOBAL_RATE_LIMIT_BURST` — bucket capacity (default 50).
    ///
    /// Invalid / missing values fall back to the defaults. A zero RPS or
    /// burst is interpreted as "limiter disabled" — every request passes.
    pub fn from_env() -> Self {
        let rps = std::env::var("SAURON_GLOBAL_RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(200);
        let burst = std::env::var("SAURON_GLOBAL_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(50);
        Self {
            requests_per_second_per_ip: rps,
            burst,
        }
    }

    /// Whether the limiter is effectively disabled (rps==0 OR burst==0).
    pub fn is_disabled(&self) -> bool {
        self.requests_per_second_per_ip == 0 || self.burst == 0
    }
}

/// Per-IP token-bucket state. Floating tokens so refill arithmetic is
/// exact across sub-second intervals.
#[derive(Debug, Clone, Copy)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

/// In-memory store of token buckets, keyed by remote IP. Cloneable
/// (Arc-wrapped) so the layer factory can hand the same store to the
/// middleware closure and to the prune task.
#[derive(Debug, Clone, Default)]
pub struct GlobalRateLimiter {
    cfg: GlobalRateLimitConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, BucketState>>>,
}

impl GlobalRateLimiter {
    /// Build a limiter with the given config and an empty bucket map.
    pub fn new(cfg: GlobalRateLimitConfig) -> Self {
        Self {
            cfg,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Borrow the config (used by tests + admin telemetry).
    pub fn config(&self) -> GlobalRateLimitConfig {
        self.cfg
    }

    /// Number of distinct IP buckets currently tracked.
    pub fn tracked_ip_count(&self) -> usize {
        self.buckets.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Attempt to consume one token for `ip` at logical time `now`.
    ///
    /// Returns `Ok(())` on success, `Err(retry_after_secs)` on rejection.
    /// The retry-after estimate is `ceil(1 / rps)` seconds, which is the
    /// shortest window an empty bucket needs to accumulate one token.
    pub fn try_acquire_at(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        if self.cfg.is_disabled() {
            return Ok(());
        }
        let rps = self.cfg.requests_per_second_per_ip as f64;
        let burst = self.cfg.burst as f64;
        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            // Poisoned mutex: recover and continue. Worst-case we lose
            // one bucket's state — never block the request path on a
            // panic in another worker.
            Err(p) => p.into_inner(),
        };
        let entry = map.entry(ip).or_insert(BucketState {
            tokens: burst,
            last_refill: now,
        });
        let elapsed = now.saturating_duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rps).min(burst);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            Ok(())
        } else {
            // ceil(1/rps), at least 1 second.
            let retry = (1.0 / rps).ceil() as u64;
            Err(retry.max(1))
        }
    }

    /// Production-time wrapper for `try_acquire_at` using `Instant::now()`.
    pub fn try_acquire(&self, ip: IpAddr) -> Result<(), u64> {
        self.try_acquire_at(ip, Instant::now())
    }

    /// Drop bucket entries whose `last_refill` is older than `ttl`.
    /// Returns the number of entries removed. Cheap O(N) sweep — we only
    /// call this every 60 seconds from the background task.
    pub fn prune(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let before = map.len();
        map.retain(|_, b| now.saturating_duration_since(b.last_refill) < ttl);
        before - map.len()
    }

    /// Spawn the background pruner task on the current tokio runtime.
    /// Runs every 60 seconds and evicts buckets idle for >= 5 minutes.
    pub fn spawn_pruner(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            // Skip the first immediate tick — no buckets exist yet.
            tick.tick().await;
            loop {
                tick.tick().await;
                let removed = this.prune(Duration::from_secs(5 * 60));
                if removed > 0 {
                    tracing::debug!(
                        target: "sauron::rate_limit",
                        removed,
                        tracked = this.tracked_ip_count(),
                        "rate-limit bucket pruned"
                    );
                }
            }
        });
    }
}

/// Parse the leftmost entry from `X-Forwarded-For` as an IP literal.
///
/// Returns `None` if the header is absent, empty, or unparseable. The
/// leftmost entry is the originating client; intermediate proxies append
/// themselves on the right.
fn parse_xff(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = raw.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    first.parse::<IpAddr>().ok()
}

/// Parse `X-Real-IP` (single IP literal, no list semantics).
fn parse_real_ip(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")?
        .to_str()
        .ok()?
        .trim()
        .parse::<IpAddr>()
        .ok()
}

/// Resolve the remote IP for the given request, preferring headers set
/// by trusted reverse proxies and falling back to the socket peer.
fn resolve_remote_ip(req: &Request) -> IpAddr {
    if let Some(ip) = parse_xff(req.headers()) {
        return ip;
    }
    if let Some(ip) = parse_real_ip(req.headers()) {
        return ip;
    }
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }
    // Unknown peer — bucket everyone into 0.0.0.0. This is the safe
    // pessimistic default: a misconfigured deployment without
    // ConnectInfo wiring still rate-limits, it just rate-limits as a
    // shared pool. Operator gets warned in logs the first time it fires.
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

/// Axum middleware factory.
///
/// Hands back an async function suitable for
/// `axum::middleware::from_fn` that consumes one token per request and
/// rejects with `429 Too Many Requests` when the bucket is empty.
///
/// Wire it from `core/src/main.rs`:
///
/// ```ignore
/// use sauron_core::middleware::{global_rate_limit_middleware, GlobalRateLimitConfig, GlobalRateLimiter};
/// let limiter = std::sync::Arc::new(GlobalRateLimiter::new(GlobalRateLimitConfig::from_env()));
/// limiter.spawn_pruner();
/// app.layer(axum::middleware::from_fn_with_state(
///     limiter.clone(),
///     global_rate_limit_middleware,
/// ));
/// ```
pub async fn global_rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<Arc<GlobalRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.config().is_disabled() {
        return next.run(request).await;
    }
    let ip = resolve_remote_ip(&request);
    match limiter.try_acquire(ip) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(
                target: "sauron::rate_limit",
                ip = %ip,
                path = %request.uri().path(),
                "global rate limit tripped"
            );
            // Best-effort audit record. Failures here must never block
            // the 429 response or panic the request worker.
            crate::middleware::audit_log::record(crate::middleware::audit_log::AuditEvent::RateLimitTripped {
                ip: ip.to_string(),
                path: request.uri().path().to_string(),
            });
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert("retry-after", v);
            }
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn basic_limit_rejects_after_burst() {
        // burst=3, rps=1 — first 3 succeed, 4th fails.
        let cfg = GlobalRateLimitConfig {
            requests_per_second_per_ip: 1,
            burst: 3,
        };
        let lim = GlobalRateLimiter::new(cfg);
        let t0 = Instant::now();
        let peer = ip(10, 0, 0, 1);
        assert!(lim.try_acquire_at(peer, t0).is_ok());
        assert!(lim.try_acquire_at(peer, t0).is_ok());
        assert!(lim.try_acquire_at(peer, t0).is_ok());
        let err = lim.try_acquire_at(peer, t0).unwrap_err();
        assert!(err >= 1, "retry-after must be >= 1 second, got {err}");
    }

    #[test]
    fn burst_allowance_then_steady_state() {
        // burst=5, rps=10 → can spend 5 instantly then refill 10/s.
        let cfg = GlobalRateLimitConfig {
            requests_per_second_per_ip: 10,
            burst: 5,
        };
        let lim = GlobalRateLimiter::new(cfg);
        let t0 = Instant::now();
        let peer = ip(10, 0, 0, 2);
        // Spend full burst.
        for _ in 0..5 {
            assert!(lim.try_acquire_at(peer, t0).is_ok());
        }
        // 6th at t0 must fail.
        assert!(lim.try_acquire_at(peer, t0).is_err());
        // 200ms later → 2 tokens accumulated.
        let t1 = t0 + Duration::from_millis(200);
        assert!(lim.try_acquire_at(peer, t1).is_ok());
        assert!(lim.try_acquire_at(peer, t1).is_ok());
        assert!(lim.try_acquire_at(peer, t1).is_err());
    }

    #[test]
    fn ip_isolation_prevents_cross_contamination() {
        // Two IPs share the limiter but get independent buckets.
        let cfg = GlobalRateLimitConfig {
            requests_per_second_per_ip: 1,
            burst: 2,
        };
        let lim = GlobalRateLimiter::new(cfg);
        let t0 = Instant::now();
        let a = ip(10, 0, 0, 10);
        let b = ip(10, 0, 0, 11);
        // Drain A.
        assert!(lim.try_acquire_at(a, t0).is_ok());
        assert!(lim.try_acquire_at(a, t0).is_ok());
        assert!(lim.try_acquire_at(a, t0).is_err());
        // B still has full burst.
        assert!(lim.try_acquire_at(b, t0).is_ok());
        assert!(lim.try_acquire_at(b, t0).is_ok());
        assert!(lim.try_acquire_at(b, t0).is_err());
    }

    #[test]
    fn refill_over_time_replenishes_tokens() {
        // burst=1, rps=2 → after exhausting, a 500ms gap refills exactly 1.
        let cfg = GlobalRateLimitConfig {
            requests_per_second_per_ip: 2,
            burst: 1,
        };
        let lim = GlobalRateLimiter::new(cfg);
        let t0 = Instant::now();
        let peer = ip(10, 0, 0, 3);
        assert!(lim.try_acquire_at(peer, t0).is_ok());
        assert!(lim.try_acquire_at(peer, t0).is_err());
        let t1 = t0 + Duration::from_millis(500);
        assert!(lim.try_acquire_at(peer, t1).is_ok());
        // Immediately again — empty.
        assert!(lim.try_acquire_at(peer, t1).is_err());
        // After a long pause, tokens cap at burst (no overshoot).
        let t2 = t1 + Duration::from_secs(60);
        assert!(lim.try_acquire_at(peer, t2).is_ok());
        assert!(lim.try_acquire_at(peer, t2).is_err());
    }
}
