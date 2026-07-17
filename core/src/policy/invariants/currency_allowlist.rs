//! Currency-allowlist invariant.
//!
//! Denies any action whose `metadata.currency` is missing or not in the
//! configured allowlist. Reads `binding.currency_allowlist` and the
//! per-action `currency` metadata field (ISO 4217 code: `EUR`, `USD`,
//! `GBP`, …). Use this on payment agents that must only move money in a
//! sanctioned currency set.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Allowed ISO 4217 currency set.
#[derive(Debug, Clone)]
pub struct CurrencyAllowlistCheck {
    allowed: HashSet<String>,
}

impl CurrencyAllowlistCheck {
    /// Build from a list of allowed currency codes. Codes are uppercased
    /// for comparison (`eur` and `EUR` both match an `EUR` entry).
    pub fn new(allowed: Vec<String>) -> Self {
        Self {
            allowed: allowed
                .into_iter()
                .map(|s| s.to_ascii_uppercase())
                .collect(),
        }
    }
}

impl RuntimeCheck for CurrencyAllowlistCheck {
    fn name(&self) -> &'static str {
        "currency_allowlist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(raw) = ctx.action.metadata.get("currency").and_then(|v| v.as_str()) else {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: "action.metadata.currency missing".to_string(),
            };
        };
        let code = raw.to_ascii_uppercase();
        if self.allowed.contains(&code) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("currency '{code}' not in allowlist"),
            }
        }
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

    fn action_with(c: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(s) = c {
            a.metadata.insert("currency".into(), json!(s));
        }
        a
    }

    #[test]
    fn allows_when_in_list() {
        let c = CurrencyAllowlistCheck::new(vec!["EUR".into(), "USD".into()]);
        let a = action_with(Some("EUR"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn case_insensitive() {
        let c = CurrencyAllowlistCheck::new(vec!["eur".into()]);
        let a = action_with(Some("EUR"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_list() {
        let c = CurrencyAllowlistCheck::new(vec!["EUR".into()]);
        let a = action_with(Some("GBP"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn missing_currency_denies() {
        let c = CurrencyAllowlistCheck::new(vec!["EUR".into()]);
        let a = action_with(None);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
