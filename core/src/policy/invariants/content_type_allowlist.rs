//! Content-type allowlist invariant.
//!
//! Denies any action whose `metadata.content_type` is missing or not in
//! the configured allowlist. Reads `binding.content_type_allowlist` and
//! the per-action `content_type` metadata field. Use this to restrict
//! what MIME types an agent can produce/upload (e.g. allow
//! `application/json` + `text/plain` only).

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// MIME-type allowlist. Comparison is case-insensitive — we normalise
/// both sides to lowercase before matching.
#[derive(Debug, Clone)]
pub struct ContentTypeCheck {
    allowed: HashSet<String>,
}

impl ContentTypeCheck {
    /// Build from a list of allowed content-type strings.
    pub fn new(allowed: Vec<String>) -> Self {
        Self {
            allowed: allowed
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl RuntimeCheck for ContentTypeCheck {
    fn name(&self) -> &'static str {
        "content_type_allowlist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(raw) = ctx
            .action
            .metadata
            .get("content_type")
            .and_then(|v| v.as_str())
        else {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: "action.metadata.content_type missing".to_string(),
            };
        };
        // Strip MIME parameters (`; charset=utf-8`) before comparison.
        let ct = raw
            .split(';')
            .next()
            .unwrap_or(raw)
            .trim()
            .to_ascii_lowercase();
        if self.allowed.contains(&ct) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("content type '{ct}' not in allowlist"),
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

    fn action_with(ct: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(c) = ct {
            a.metadata.insert("content_type".into(), json!(c));
        }
        a
    }

    #[test]
    fn allows_when_in_list() {
        let c = ContentTypeCheck::new(vec!["application/json".into()]);
        let a = action_with(Some("application/json"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn strips_mime_parameters() {
        let c = ContentTypeCheck::new(vec!["text/plain".into()]);
        let a = action_with(Some("text/plain; charset=utf-8"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_list() {
        let c = ContentTypeCheck::new(vec!["application/json".into()]);
        let a = action_with(Some("text/html"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn missing_content_type_denies() {
        let c = ContentTypeCheck::new(vec!["application/json".into()]);
        let a = action_with(None);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
