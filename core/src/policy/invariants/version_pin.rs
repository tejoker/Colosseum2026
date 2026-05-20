//! Version-pin invariant.
//!
//! Denies any action whose `metadata.agent_version` does not match the
//! configured pinned version. Reads `binding.pinned_version` and the
//! per-action `agent_version` metadata field. Use this as an anti-drift
//! tool: a known-good agent build is signed off and you want to block
//! all other versions until a new approval lands.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Exact-match version pin (e.g. `"1.4.2"` or `"sha256:abcd..."`).
#[derive(Debug, Clone)]
pub struct VersionPinCheck {
    pinned: String,
}

impl VersionPinCheck {
    /// Build from the configured version string. Comparison is exact and
    /// case-sensitive — semver-aware ranges are out of scope here.
    pub fn new(pinned: String) -> Self {
        Self { pinned }
    }
}

impl RuntimeCheck for VersionPinCheck {
    fn name(&self) -> &'static str {
        "version_pin"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(v) = ctx
            .action
            .metadata
            .get("agent_version")
            .and_then(|x| x.as_str())
        else {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: "action.metadata.agent_version missing".to_string(),
            };
        };
        if v == self.pinned {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("agent_version '{v}' does not match pinned '{}'", self.pinned),
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

    fn action_with(v: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(s) = v {
            a.metadata.insert("agent_version".into(), json!(s));
        }
        a
    }

    #[test]
    fn allows_matching_version() {
        let c = VersionPinCheck::new("1.4.2".into());
        let a = action_with(Some("1.4.2"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_mismatch() {
        let c = VersionPinCheck::new("1.4.2".into());
        let a = action_with(Some("1.4.3"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn case_sensitive() {
        let c = VersionPinCheck::new("v1.0".into());
        let a = action_with(Some("V1.0"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn missing_version_denies() {
        let c = VersionPinCheck::new("1.0.0".into());
        let a = action_with(None);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
