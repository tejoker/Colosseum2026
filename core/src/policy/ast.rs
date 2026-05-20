//! Abstract syntax tree for the policy DSL.
//!
//! Every public struct here is `Serialize + Deserialize + Debug + Clone +
//! PartialEq`. Top-level structs use `#[serde(deny_unknown_fields)]` to
//! catch typos at parse time — `Metadata` is intentionally extensible.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A complete agent-binding policy. Top-level document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// DSL version string. Currently always `"1"`.
    pub version: String,
    /// Identifier or human label for the agent this policy binds.
    pub agent: String,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Binding section — what the agent is allowed to do.
    #[serde(default)]
    pub binding: Binding,
    /// First-class invariant predicate strings. Parsed at runtime in Sprint 2.
    #[serde(default)]
    pub invariants: Vec<String>,
    /// Optional metadata (creation time, author, freeform tags).
    #[serde(default)]
    pub metadata: Metadata,
}

/// Binding — declarative limits on agent behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Optional explicit tool allowlist. Absent => any tool permitted by
    /// upstream policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    /// Optional maximum spend in USD over the policy lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_budget_usd: Option<f64>,
    /// Optional classification-based data scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_scope: Option<DataScope>,
    /// Optional request-rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Optional wall-clock window where the agent may act.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Optional M-of-N signature requirements (Sprint 2 invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_signatures: Option<Vec<SignatureRequirement>>,
    /// Optional limits on sub-agent delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationLimits>,
    // ─── Sprint 3 additive fields — all optional, all default `None` ───
    /// Outbound-domain allowlist consumed by `DomainAllowlistCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_allowlist: Option<Vec<String>>,
    /// Outbound-domain denylist consumed by `DomainDenylistCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_denylist: Option<Vec<String>>,
    /// Tool denylist consumed by `ToolDenylistCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_denylist: Option<Vec<String>>,
    /// Daily spend cap (USD) consumed by `DailyBudgetCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_budget_usd: Option<f64>,
    /// Per-action spend cap (USD) consumed by `PerActionCapCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_single_action_usd: Option<f64>,
    /// Weekly rate limit consumed by `WeeklyRateCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_rate: Option<WeeklyRate>,
    /// Maximum simultaneous in-flight actions for `ConcurrencyCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,
    /// Cooldown gap (seconds) consumed by `CooldownCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    /// Max payload size in bytes consumed by `PayloadSizeCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    /// MIME allowlist consumed by `ContentTypeCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type_allowlist: Option<Vec<String>>,
    /// Per-action recipient count cap consumed by `RecipientCountCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recipients: Option<u32>,
    /// Max agent-call chain depth consumed by `ChainDepthCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chain_depth: Option<u32>,
    /// When `Some(true)`, registers `PiiDetectionCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_block: Option<bool>,
    /// Natural-language allowlist consumed by `LanguageAllowlistCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_allowlist: Option<Vec<String>>,
    /// ISO 4217 currency allowlist consumed by `CurrencyAllowlistCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency_allowlist: Option<Vec<String>>,
    /// ISO 3166 allow-country list consumed by `GeoRestrictionCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_allow_countries: Option<Vec<String>>,
    /// ISO 3166 deny-country list consumed by `GeoRestrictionCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_deny_countries: Option<Vec<String>>,
    /// Per-weekday business hours consumed by `BusinessHoursCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_hours: Option<BusinessHours>,
    /// Holiday blackout dates (`YYYY-MM-DD`) for `HolidayBlackoutCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holiday_blackout_dates: Option<Vec<String>>,
    /// Exact agent-version pin consumed by `VersionPinCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<String>,
    /// When `Some(true)`, registers `DryRunCheck`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// Weekly request-rate limit consumed by [`WeeklyRateCheck`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklyRate {
    /// Maximum requests per rolling 7-day window. Must be > 0.
    pub requests_per_week: u32,
}

/// Per-weekday business-hours config consumed by [`BusinessHoursCheck`].
///
/// `weekday_windows` keys are 0=Sunday..6=Saturday. Each value is a
/// `[start, end]` `HH:MM` pair. Days absent from the map are treated as
/// non-business — the agent is fully blocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusinessHours {
    /// 0=Sunday..6=Saturday → `[start, end]` HH:MM pair. Backed by
    /// `BTreeMap` so serialisation order is deterministic and policy IDs
    /// stay stable across runs.
    pub weekday_windows: BTreeMap<u8, [String; 2]>,
    /// IANA timezone.
    pub timezone: String,
}

/// Classification-tag based data access scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataScope {
    /// Classification tags the agent may operate on.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Classification tags the agent must never touch (takes precedence).
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Token-bucket-style rate limit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Maximum requests per minute. Must be > 0.
    pub requests_per_minute: u32,
}

/// Wall-clock window in which the agent may act.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// Window start, `HH:MM` 24-hour, leading zeros required.
    pub start: String,
    /// Window end, `HH:MM` 24-hour, leading zeros required.
    pub end: String,
    /// IANA timezone (e.g. `Europe/Paris`).
    pub timezone: String,
}

/// One signature requirement clause inside `required_signatures`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRequirement {
    /// Role name expected to sign (e.g. `human_approver`, `clinician`).
    pub role: String,
    /// M-of-N threshold — number of distinct signatures required for this role.
    pub threshold: u32,
}

/// Limits on how the agent may delegate work to sub-agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLimits {
    /// Maximum delegation depth (0 disables delegation).
    pub max_depth: u32,
    /// Allowed sub-agent identifiers.
    #[serde(default)]
    pub allowed_subagents: Vec<String>,
}

/// Free-form metadata. Intentionally not `deny_unknown_fields` so operators
/// can attach arbitrary tooling-specific keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// ISO-8601 date of creation (free-form string at this layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Author identifier (email, handle, anything).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Free-form tags for search/grouping.
    #[serde(default)]
    pub tags: Vec<String>,
}
