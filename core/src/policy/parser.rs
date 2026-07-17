//! YAML/JSON parser for the policy DSL.
//!
//! Two stages:
//! 1. **Deserialise** input into [`Policy`] via serde (`serde_yml` /
//!    `serde_json`). Unknown top-level fields are rejected because every
//!    struct except `Metadata` has `#[serde(deny_unknown_fields)]`.
//! 2. **Semantic validate** the parsed AST: version pin, time/tz format,
//!    non-negative budget, non-empty rate limit, no allow/deny overlap.
//!
//! Both stages return [`PolicyParseError`]. The public entry points are
//! [`parse`], [`parse_yaml`], [`parse_json`].

use super::ast::Policy;
use super::types::{validate_hhmm, validate_iana_tz, PolicyParseError};

/// Current DSL version. Anything else triggers `UnsupportedVersion`.
pub const SUPPORTED_VERSION: &str = "1";

/// Parse a policy document, auto-detecting JSON (`{`-prefixed) vs YAML.
///
/// Leading whitespace is skipped before sniffing.
pub fn parse(input: &str) -> Result<Policy, PolicyParseError> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') {
        parse_json(input)
    } else {
        parse_yaml(input)
    }
}

/// Parse a YAML policy document.
pub fn parse_yaml(input: &str) -> Result<Policy, PolicyParseError> {
    let policy: Policy =
        serde_yaml_ng::from_str(input).map_err(|e| PolicyParseError::InvalidYaml(e.to_string()))?;
    validate(&policy)?;
    Ok(policy)
}

/// Parse a JSON policy document.
pub fn parse_json(input: &str) -> Result<Policy, PolicyParseError> {
    let policy: Policy =
        serde_json::from_str(input).map_err(|e| PolicyParseError::InvalidJson(e.to_string()))?;
    validate(&policy)?;
    Ok(policy)
}

/// Run semantic validation on a structurally-parsed policy.
///
/// Public so callers that build policies programmatically can validate
/// without round-tripping through serde.
pub fn validate(policy: &Policy) -> Result<(), PolicyParseError> {
    // version pin
    if policy.version != SUPPORTED_VERSION {
        return Err(PolicyParseError::UnsupportedVersion(format!(
            "expected version \"{SUPPORTED_VERSION}\", got \"{}\"",
            policy.version
        )));
    }

    // agent must be non-empty
    if policy.agent.trim().is_empty() {
        return Err(PolicyParseError::SchemaViolation(
            "`agent` must be non-empty".to_string(),
        ));
    }

    // budget non-negative + finite
    if let Some(b) = policy.binding.max_budget_usd {
        if !b.is_finite() || b < 0.0 {
            return Err(PolicyParseError::SchemaViolation(format!(
                "`binding.max_budget_usd` must be a finite, non-negative number, got {b}"
            )));
        }
    }

    // rate limit > 0
    if let Some(rl) = &policy.binding.rate_limit {
        if rl.requests_per_minute == 0 {
            return Err(PolicyParseError::SchemaViolation(
                "`binding.rate_limit.requests_per_minute` must be > 0".to_string(),
            ));
        }
    }

    // time window: HHMM + IANA tz
    if let Some(tw) = &policy.binding.time_window {
        validate_hhmm(&tw.start)?;
        validate_hhmm(&tw.end)?;
        validate_iana_tz(&tw.timezone)?;
    }

    // data_scope: allow ∩ deny must be empty
    if let Some(ds) = &policy.binding.data_scope {
        let conflict: Vec<&String> = ds.allow.iter().filter(|t| ds.deny.contains(t)).collect();
        if !conflict.is_empty() {
            return Err(PolicyParseError::SchemaViolation(format!(
                "`binding.data_scope.allow` and `.deny` must be disjoint; overlap: {conflict:?}"
            )));
        }
    }

    // signature requirement thresholds must be > 0
    if let Some(sigs) = &policy.binding.required_signatures {
        for s in sigs {
            if s.threshold == 0 {
                return Err(PolicyParseError::SchemaViolation(format!(
                    "`required_signatures[role={}].threshold` must be > 0",
                    s.role
                )));
            }
            if s.role.trim().is_empty() {
                return Err(PolicyParseError::SchemaViolation(
                    "`required_signatures[].role` must be non-empty".to_string(),
                ));
            }
        }
    }

    // ─── Sprint 3 additive-field validation ──────────────────────────────
    if let Some(b) = policy.binding.daily_budget_usd {
        if !b.is_finite() || b < 0.0 {
            return Err(PolicyParseError::SchemaViolation(format!(
                "`binding.daily_budget_usd` must be a finite, non-negative number, got {b}"
            )));
        }
    }
    if let Some(b) = policy.binding.max_single_action_usd {
        if !b.is_finite() || b < 0.0 {
            return Err(PolicyParseError::SchemaViolation(format!(
                "`binding.max_single_action_usd` must be a finite, non-negative number, got {b}"
            )));
        }
    }
    if let Some(wr) = &policy.binding.weekly_rate {
        if wr.requests_per_week == 0 {
            return Err(PolicyParseError::SchemaViolation(
                "`binding.weekly_rate.requests_per_week` must be > 0".to_string(),
            ));
        }
    }
    if let Some(bh) = &policy.binding.business_hours {
        validate_iana_tz(&bh.timezone)?;
        for (wd, [s, e]) in &bh.weekday_windows {
            if *wd > 6 {
                return Err(PolicyParseError::SchemaViolation(format!(
                    "`business_hours.weekday_windows` key must be 0..=6 (got {wd})"
                )));
            }
            validate_hhmm(s)?;
            validate_hhmm(e)?;
        }
    }
    if let Some(dates) = &policy.binding.holiday_blackout_dates {
        for d in dates {
            if !is_yyyy_mm_dd(d) {
                return Err(PolicyParseError::SchemaViolation(format!(
                    "`holiday_blackout_dates` entry must be YYYY-MM-DD, got '{d}'"
                )));
            }
        }
    }

    Ok(())
}

/// Lightweight `YYYY-MM-DD` shape check. We deliberately don't try to
/// validate the calendar date (chrono can do that at a later cost); this
/// catches the most common typos.
fn is_yyyy_mm_dd(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    for i in [0usize, 1, 2, 3, 5, 6, 8, 9] {
        if !bytes[i].is_ascii_digit() {
            return false;
        }
    }
    true
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture loaders — each is `include_str!` so missing files fail at
    // compile time, not at test runtime.
    const FX_BANKING: &str =
        include_str!("../../../schemas/fixtures/policy_banking_payment_agent.yaml");
    const FX_HEALTHCARE: &str =
        include_str!("../../../schemas/fixtures/policy_healthcare_records.yaml");
    const FX_DEVTOOLS: &str =
        include_str!("../../../schemas/fixtures/policy_devtools_codegen.yaml");
    const FX_RESEARCH: &str =
        include_str!("../../../schemas/fixtures/policy_research_assistant.yaml");
    const FX_SUPPORT: &str =
        include_str!("../../../schemas/fixtures/policy_customer_support_chatbot.yaml");
    const FX_MARKETING: &str =
        include_str!("../../../schemas/fixtures/policy_marketing_content.yaml");
    const FX_LEGAL: &str = include_str!("../../../schemas/fixtures/policy_legal_review.yaml");
    const FX_ANALYST: &str = include_str!("../../../schemas/fixtures/policy_data_analyst.yaml");
    const FX_TREASURY: &str = include_str!("../../../schemas/fixtures/policy_treasury_ops.yaml");
    const FX_MINIMAL: &str = include_str!("../../../schemas/fixtures/policy_minimal.yaml");

    #[test]
    fn fixture_banking_parses() {
        let p = parse(FX_BANKING).expect("banking fixture parses");
        assert_eq!(p.version, "1");
        assert_eq!(p.agent, "payment_agent_eu");
        assert_eq!(p.binding.max_budget_usd, Some(5000.0));
        let tw = p.binding.time_window.as_ref().expect("time window set");
        assert_eq!(tw.timezone, "Europe/Paris");
        assert!(!p.binding.allowed_tools.as_ref().unwrap().is_empty());
    }

    #[test]
    fn fixture_healthcare_parses() {
        let p = parse(FX_HEALTHCARE).expect("healthcare fixture parses");
        let sigs = p.binding.required_signatures.as_ref().unwrap();
        assert!(sigs.iter().any(|s| s.threshold == 2));
        let ds = p.binding.data_scope.as_ref().unwrap();
        assert!(ds.deny.iter().any(|t| t == "pii"));
    }

    #[test]
    fn fixture_devtools_parses() {
        let p = parse(FX_DEVTOOLS).expect("devtools fixture parses");
        assert_eq!(p.agent, "codegen_assistant");
        assert!(p.invariants.iter().any(|s| s.contains("no_external_call")));
    }

    #[test]
    fn fixture_research_parses() {
        let p = parse(FX_RESEARCH).expect("research fixture parses");
        assert!(p.binding.time_window.is_some());
        assert!(p.binding.allowed_tools.is_some());
    }

    #[test]
    fn fixture_support_parses() {
        let p = parse(FX_SUPPORT).expect("support fixture parses");
        let rl = p.binding.rate_limit.as_ref().unwrap();
        assert!(rl.requests_per_minute >= 60);
        let ds = p.binding.data_scope.as_ref().unwrap();
        assert!(ds.allow.iter().any(|t| t == "public"));
    }

    #[test]
    fn fixture_marketing_parses() {
        let p = parse(FX_MARKETING).expect("marketing fixture parses");
        assert!(p
            .invariants
            .iter()
            .any(|s| s.contains("posting_domain") || s.contains("allowed_domain")));
    }

    #[test]
    fn fixture_legal_parses() {
        let p = parse(FX_LEGAL).expect("legal fixture parses");
        let sigs = p.binding.required_signatures.as_ref().unwrap();
        assert!(sigs.iter().any(|s| s.role == "partner"));
    }

    #[test]
    fn fixture_analyst_parses() {
        let p = parse(FX_ANALYST).expect("analyst fixture parses");
        let ds = p.binding.data_scope.as_ref().unwrap();
        assert!(ds.deny.iter().any(|t| t == "pii"));
    }

    #[test]
    fn fixture_treasury_parses() {
        let p = parse(FX_TREASURY).expect("treasury fixture parses");
        assert!(p.binding.max_budget_usd.is_some());
        assert!(p.binding.required_signatures.as_ref().unwrap().len() >= 2);
    }

    #[test]
    fn fixture_minimal_parses() {
        let p = parse(FX_MINIMAL).expect("minimal fixture parses");
        assert_eq!(p.version, "1");
        assert_eq!(p.invariants.len(), 1);
        assert!(p.binding.allowed_tools.is_none());
    }

    // ─── negative cases ──────────────────────────────────────────────────

    #[test]
    fn rejects_bad_timezone() {
        let yaml = r#"
version: "1"
agent: bad_tz
binding:
  time_window: { start: "09:00", end: "18:00", timezone: "Europe/Wakanda" }
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_bad_hhmm_no_leading_zero() {
        let yaml = r#"
version: "1"
agent: bad_time
binding:
  time_window: { start: "9:00", end: "18:00", timezone: "UTC" }
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_negative_budget() {
        let yaml = r#"
version: "1"
agent: broke
binding:
  max_budget_usd: -10
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_allow_deny_intersection() {
        let yaml = r#"
version: "1"
agent: conflicted
binding:
  data_scope:
    allow: [public, pii]
    deny: [pii]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = r#"
version: "1"
agent: typo_agent
boundinng: {}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::InvalidYaml(_)));
    }

    #[test]
    fn rejects_missing_version() {
        let yaml = r#"
agent: no_ver
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::InvalidYaml(_)));
    }

    #[test]
    fn rejects_missing_agent() {
        let yaml = r#"
version: "1"
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::InvalidYaml(_)));
    }

    #[test]
    fn rejects_unsupported_version() {
        let yaml = r#"
version: "2"
agent: future_proof
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::UnsupportedVersion(_)));
    }

    #[test]
    fn rejects_zero_rate_limit() {
        let yaml = r#"
version: "1"
agent: zero_rl
binding:
  rate_limit: { requests_per_minute: 0 }
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_zero_signature_threshold() {
        let yaml = r#"
version: "1"
agent: zero_sig
binding:
  required_signatures:
    - { role: human_approver, threshold: 0 }
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::SchemaViolation(_)));
    }

    #[test]
    fn json_parser_works() {
        let json =
            r#"{ "version": "1", "agent": "json_agent", "invariants": ["spend_total <= 100"] }"#;
        let p = parse(json).expect("json parses");
        assert_eq!(p.agent, "json_agent");
    }

    #[test]
    fn round_trip_preserves_ast() {
        let p1 = parse(FX_BANKING).expect("parse 1");
        let serialised = serde_yaml_ng::to_string(&p1).expect("serialise yaml");
        let p2 = parse(&serialised).expect("parse 2");
        assert_eq!(p1, p2, "round trip must preserve AST");

        // Also via JSON
        let serialised_json = serde_json::to_string(&p1).expect("serialise json");
        let p3 = parse_json(&serialised_json).expect("re-parse json");
        assert_eq!(p1, p3, "json round trip must preserve AST");
    }
}
