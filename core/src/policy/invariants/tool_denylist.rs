//! Tool denylist invariant.
//!
//! Denies any action whose `tool` field is in the configured denylist.
//! Complements `AllowlistCheck`: use the allowlist when you can enumerate
//! all permitted tools, and the denylist when you want to deny a handful
//! of dangerous ones on top of a broad default permit. Reads
//! `binding.tool_denylist`.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Tool-name denylist.
#[derive(Debug, Clone)]
pub struct ToolDenylistCheck {
    tools: HashSet<String>,
}

impl ToolDenylistCheck {
    /// Build from a list of denied tool names. Tool names are
    /// case-sensitive identifiers (`shell_exec` ≠ `SHELL_EXEC`).
    pub fn tools(tools: Vec<String>) -> Self {
        Self {
            tools: tools.into_iter().collect(),
        }
    }
}

impl RuntimeCheck for ToolDenylistCheck {
    fn name(&self) -> &'static str {
        "tool_denylist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        if self.tools.contains(&ctx.action.tool) {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("tool '{}' is on deny list", ctx.action.tool),
            }
        } else {
            Verdict::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;

    fn ctx<'a>(a: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(a)
    }

    #[test]
    fn denies_when_tool_in_list() {
        let c = ToolDenylistCheck::tools(vec!["shell_exec".into()]);
        let a = Action {
            tool: "shell_exec".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_other_tools() {
        let c = ToolDenylistCheck::tools(vec!["shell_exec".into()]);
        let a = Action {
            tool: "http_get".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn empty_list_allows_everything() {
        let c = ToolDenylistCheck::tools(vec![]);
        let a = Action {
            tool: "anything".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn case_sensitive_match() {
        let c = ToolDenylistCheck::tools(vec!["shell_exec".into()]);
        let a = Action {
            tool: "SHELL_EXEC".into(),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }
}
