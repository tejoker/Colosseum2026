//! Geo restriction invariant.
//!
//! Denies any action whose `metadata.client_country` is on the deny list
//! OR (if an allow list is configured) is missing/absent from it. Reads
//! `binding.geo_allow_countries` and `binding.geo_deny_countries` plus
//! the per-action `client_country` metadata field (ISO 3166-1 alpha-2:
//! `US`, `FR`, …). Both lists may be configured; deny takes precedence.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Geographic allow/deny lists by country code.
#[derive(Debug, Clone)]
pub struct GeoRestrictionCheck {
    allow: HashSet<String>,
    deny: HashSet<String>,
}

impl GeoRestrictionCheck {
    /// Build from allow + deny lists. Either may be empty; if both are
    /// empty the check trivially allows everything (caller should not
    /// register the check in that case but defence in depth is cheap).
    pub fn new(allow: Vec<String>, deny: Vec<String>) -> Self {
        Self {
            allow: allow.into_iter().map(|s| s.to_ascii_uppercase()).collect(),
            deny: deny.into_iter().map(|s| s.to_ascii_uppercase()).collect(),
        }
    }
}

impl RuntimeCheck for GeoRestrictionCheck {
    fn name(&self) -> &'static str {
        "geo_restriction"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let raw = ctx
            .action
            .metadata
            .get("client_country")
            .and_then(|v| v.as_str());
        let country = raw.map(|s| s.to_ascii_uppercase());
        if let Some(ref c) = country {
            if self.deny.contains(c) {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: format!("country '{c}' on geo deny list"),
                };
            }
        }
        if !self.allow.is_empty() {
            let Some(ref c) = country else {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: "action.metadata.client_country missing".to_string(),
                };
            };
            if !self.allow.contains(c) {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: format!("country '{c}' not in geo allow list"),
                };
            }
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;
    use serde_json::json;

    fn ctx<'a>(a: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(a)
    }

    fn action_with(country: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(c) = country {
            a.metadata.insert("client_country".into(), json!(c));
        }
        a
    }

    #[test]
    fn denies_in_deny_list() {
        let c = GeoRestrictionCheck::new(vec![], vec!["KP".into(), "IR".into()]);
        let a = action_with(Some("KP"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_when_in_allow_list() {
        let c = GeoRestrictionCheck::new(vec!["FR".into(), "DE".into()], vec![]);
        let a = action_with(Some("FR"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_allow_list() {
        let c = GeoRestrictionCheck::new(vec!["FR".into()], vec![]);
        let a = action_with(Some("US"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn missing_country_denies_only_when_allow_list_active() {
        let c1 = GeoRestrictionCheck::new(vec!["FR".into()], vec![]);
        let a = action_with(None);
        assert!(c1.evaluate(&ctx(&a)).is_deny());

        let c2 = GeoRestrictionCheck::new(vec![], vec!["KP".into()]);
        // Deny-only list with missing country: allow (deny can't match).
        assert!(c2.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let c = GeoRestrictionCheck::new(vec!["US".into()], vec!["US".into()]);
        let a = action_with(Some("US"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
