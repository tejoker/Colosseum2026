//! Language-allowlist invariant.
//!
//! Denies any action whose `metadata.detected_language` is missing or
//! not in the configured allowlist. Reads `binding.language_allowlist`
//! and the per-action `detected_language` metadata field (ISO 639-1 code
//! like `en`, `fr`, `de`). Use this when an agent must only respond in
//! a sanctioned set of languages (e.g. compliance requires
//! English-only).

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Allowed natural-language set (ISO 639-1).
#[derive(Debug, Clone)]
pub struct LanguageAllowlistCheck {
    allowed: HashSet<String>,
}

impl LanguageAllowlistCheck {
    /// Build from a list of allowed language codes. Comparison is
    /// case-insensitive — codes are lowercased on the way in.
    pub fn new(allowed: Vec<String>) -> Self {
        Self {
            allowed: allowed
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl RuntimeCheck for LanguageAllowlistCheck {
    fn name(&self) -> &'static str {
        "language_allowlist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(raw) = ctx
            .action
            .metadata
            .get("detected_language")
            .and_then(|v| v.as_str())
        else {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: "action.metadata.detected_language missing".to_string(),
            };
        };
        let code = raw.to_ascii_lowercase();
        if self.allowed.contains(&code) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("language '{code}' not in allowlist"),
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

    fn action_with(lang: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(l) = lang {
            a.metadata.insert("detected_language".into(), json!(l));
        }
        a
    }

    #[test]
    fn allows_when_in_list() {
        let c = LanguageAllowlistCheck::new(vec!["en".into(), "fr".into()]);
        let a = action_with(Some("en"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn case_insensitive() {
        let c = LanguageAllowlistCheck::new(vec!["EN".into()]);
        let a = action_with(Some("en"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_list() {
        let c = LanguageAllowlistCheck::new(vec!["en".into()]);
        let a = action_with(Some("zh"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn missing_language_denies() {
        let c = LanguageAllowlistCheck::new(vec!["en".into()]);
        let a = action_with(None);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
