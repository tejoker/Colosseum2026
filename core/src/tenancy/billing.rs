//! Per-tenant usage / billing scaffolding (Sprint 11.5 placeholder).
//!
//! Sprint 11 ships data isolation only — no real billing. This file fixes
//! the data shape so 11.5 can swap in a persistent backend without
//! refactoring call sites. Today every helper is a no-op; the struct is
//! `#[derive(Debug, Clone)]` so it can be passed through without lifetime
//! grief once the metering routes land.

use serde::{Deserialize, Serialize};

/// One row of per-tenant usage metering. Future schema lands in a
/// `usage_records` table — for now this is an in-memory record only
/// (anchor / aggregation pipelines DO NOT consume it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UsageRecord {
    /// The tenant this usage row is charged against.
    pub tenant_id: String,
    /// Coarse action category — `agent_register`, `policy_evaluate`,
    /// `agent_action_receipt`, `spend_record`. Free-form for S11; locked
    /// down via an enum in 11.5.
    pub action: String,
    /// Number of units consumed (calls). Quantity, not currency — billing
    /// dimensions are derived from the rate card off-line.
    pub units: u64,
    /// Unix-epoch seconds the row was recorded.
    pub recorded_at: i64,
    /// Optional free-form metadata, e.g. `{"endpoint": "/agent/register"}`.
    /// Sized for a single JSON-line of context, NOT a full audit log.
    #[serde(default)]
    pub meta_json: String,
}

impl UsageRecord {
    /// Build a minimal record; meta defaults to an empty JSON object.
    pub fn new(tenant_id: impl Into<String>, action: impl Into<String>, units: u64) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            action: action.into(),
            units,
            recorded_at: now_secs(),
            meta_json: "{}".to_string(),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_record_serialises_with_meta_default() {
        let u = UsageRecord::new("acme", "agent_register", 1);
        assert_eq!(u.tenant_id, "acme");
        assert_eq!(u.action, "agent_register");
        assert_eq!(u.units, 1);
        assert_eq!(u.meta_json, "{}");
        let j = serde_json::to_string(&u).unwrap();
        assert!(j.contains("\"tenant_id\":\"acme\""));
    }
}
