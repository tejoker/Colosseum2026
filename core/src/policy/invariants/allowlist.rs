//! Tool allowlist invariant.
//!
//! Denies any action whose `tool` is not in the configured allowlist.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Tool-name allowlist. Empty allowlist denies everything — callers
/// should not compile an `AllowlistCheck` when the policy field is
/// absent (which means "no allowlist constraint").
#[derive(Debug, Clone)]
pub struct AllowlistCheck {
    tools: HashSet<String>,
}

impl AllowlistCheck {
    /// Build from a list of allowed tool names.
    pub fn tools(tools: Vec<String>) -> Self {
        Self {
            tools: tools.into_iter().collect(),
        }
    }

    /// Number of allowed tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// `true` if no tools are allowed.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl RuntimeCheck for AllowlistCheck {
    fn name(&self) -> &'static str {
        "allowlist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        if self.tools.contains(&ctx.action.tool) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("tool '{}' not in allowlist", ctx.action.tool),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;

    fn ctx<'a>(action: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(action)
    }

    #[test]
    fn allows_when_in_list() {
        let c = AllowlistCheck::tools(vec!["http_get".into(), "sepa_payment".into()]);
        let a = Action {
            tool: "http_get".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_when_not_in_list() {
        let c = AllowlistCheck::tools(vec!["http_get".into()]);
        let a = Action {
            tool: "shell_exec".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn empty_list_denies_everything() {
        let c = AllowlistCheck::tools(vec![]);
        let a = Action {
            tool: "anything".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn case_sensitive_match() {
        // Tool names are case-sensitive identifiers — `HTTP_GET` ≠ `http_get`.
        let c = AllowlistCheck::tools(vec!["http_get".into()]);
        let a = Action {
            tool: "HTTP_GET".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
