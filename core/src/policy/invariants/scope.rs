//! Data-scope invariant.
//!
//! Enforces classification-based access:
//! - `deny` takes precedence — any action touching a denied classification
//!   is rejected unconditionally.
//! - If `allow` is non-empty, the action's classification must be in it.
//! - Actions with no `data_classification` are treated as untyped and
//!   allowed unless an explicit deny matches.

use crate::policy::ast::DataScope;
use crate::policy::types::PolicyParseError;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Allow/deny lists of data-classification tags.
#[derive(Debug, Clone)]
pub struct ScopeCheck {
    allow: Vec<String>,
    deny: Vec<String>,
}

impl ScopeCheck {
    /// Build a [`ScopeCheck`] from a parsed [`DataScope`]. The parser
    /// already guarantees `allow ∩ deny == ∅`, so this never fails today
    /// — we keep the `Result` return for forward compatibility with
    /// future per-tag validation.
    pub fn from_scope(ds: &DataScope) -> Result<Self, PolicyParseError> {
        Ok(Self {
            allow: ds.allow.iter().map(|s| s.to_ascii_lowercase()).collect(),
            deny: ds.deny.iter().map(|s| s.to_ascii_lowercase()).collect(),
        })
    }
}

impl RuntimeCheck for ScopeCheck {
    fn name(&self) -> &'static str {
        "scope"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(raw) = ctx.action.data_classification.as_deref() else {
            // No classification on the action: allow unless any explicit
            // deny is configured AND policy says untyped data is denied.
            // We choose the more permissive path: untyped → allow.
            return Verdict::Allow;
        };
        let tag = raw.to_ascii_lowercase();
        if self.deny.iter().any(|d| d == &tag) {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("classification '{tag}' is on deny list"),
            };
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|a| a == &tag) {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "classification '{tag}' not in allow list {:?}",
                    self.allow
                ),
            };
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;

    fn ctx<'a>(action: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(action)
    }

    fn scope(allow: &[&str], deny: &[&str]) -> ScopeCheck {
        ScopeCheck::from_scope(&DataScope {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        })
        .unwrap()
    }

    #[test]
    fn allows_when_classification_in_allow() {
        let s = scope(&["public", "customer_owned"], &["pii"]);
        let a = Action {
            data_classification: Some("public".into()),
            ..Default::default()
        };
        assert!(s.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_classification_in_deny() {
        let s = scope(&["public"], &["pii"]);
        let a = Action {
            data_classification: Some("PII".into()),
            ..Default::default()
        };
        let v = s.evaluate(&ctx(&a));
        assert!(v.is_deny());
    }

    #[test]
    fn denies_when_not_in_non_empty_allow() {
        let s = scope(&["public"], &[]);
        let a = Action {
            data_classification: Some("financial".into()),
            ..Default::default()
        };
        assert!(s.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_untyped_action() {
        let s = scope(&["public"], &["pii"]);
        let a = Action {
            data_classification: None,
            ..Default::default()
        };
        assert!(s.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn empty_allow_means_no_allowlist_constraint() {
        let s = scope(&[], &["pii"]);
        let a = Action {
            data_classification: Some("anything".into()),
            ..Default::default()
        };
        assert!(s.evaluate(&ctx(&a)).is_allow());
    }
}
