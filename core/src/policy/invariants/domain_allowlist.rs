//! Domain allowlist invariant.
//!
//! Denies any action whose `metadata.target_domain` is absent from the
//! configured allowlist. Reads `binding.domain_allowlist` and the
//! per-action `target_domain` metadata field. Use this when the agent
//! makes outbound network calls and you want to restrict them to a fixed
//! set of hosts (e.g. only `api.stripe.com`, `api.example.com`).

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Outbound-domain allowlist. Action denied if `target_domain` is missing
/// or not in the configured set.
#[derive(Debug, Clone)]
pub struct DomainAllowlistCheck {
    domains: HashSet<String>,
}

impl DomainAllowlistCheck {
    /// Build from a list of allowed domains. Comparison is case-insensitive
    /// on the wire — we lowercase at construction.
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl RuntimeCheck for DomainAllowlistCheck {
    fn name(&self) -> &'static str {
        "domain_allowlist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let raw = match ctx
            .action
            .metadata
            .get("target_domain")
            .and_then(|v| v.as_str())
        {
            Some(d) => d.to_ascii_lowercase(),
            None => {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: "action.metadata.target_domain missing".to_string(),
                }
            }
        };
        if self.domains.contains(&raw) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("domain '{raw}' not in allowlist"),
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

    fn action_with(domain: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(d) = domain {
            a.metadata.insert("target_domain".into(), json!(d));
        }
        a
    }

    #[test]
    fn allows_when_in_list() {
        let c = DomainAllowlistCheck::new(vec!["api.example.com".into()]);
        let a = action_with(Some("api.example.com"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_list() {
        let c = DomainAllowlistCheck::new(vec!["api.example.com".into()]);
        let a = action_with(Some("evil.com"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn case_insensitive() {
        let c = DomainAllowlistCheck::new(vec!["API.example.com".into()]);
        let a = action_with(Some("api.EXAMPLE.com"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn missing_domain_denies() {
        let c = DomainAllowlistCheck::new(vec!["api.example.com".into()]);
        let a = action_with(None);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
