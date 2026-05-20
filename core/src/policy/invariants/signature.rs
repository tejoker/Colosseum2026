//! M-of-N signature invariant.
//!
//! For each `(role, threshold)` requirement, the action's `signatures`
//! vector must contain at least `threshold` entries equal to `role`.
//! Duplicates are counted — the caller is responsible for ensuring
//! distinctness if that matters (e.g. by deduping signers by identity
//! before populating `signatures`).

use crate::policy::ast::SignatureRequirement;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// One or more `(role, threshold)` requirements that must ALL be met.
#[derive(Debug, Clone)]
pub struct SignatureCheck {
    requirements: Vec<SignatureRequirement>,
}

impl SignatureCheck {
    /// Build from the parsed `required_signatures` clause.
    pub fn from_required(reqs: Vec<SignatureRequirement>) -> Self {
        Self { requirements: reqs }
    }

    /// Number of role-clauses configured.
    pub fn len(&self) -> usize {
        self.requirements.len()
    }

    /// `true` if no requirements are configured.
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }
}

impl RuntimeCheck for SignatureCheck {
    fn name(&self) -> &'static str {
        "signatures"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        for req in &self.requirements {
            let got: u32 = ctx
                .action
                .signatures
                .iter()
                .filter(|s| *s == &req.role)
                .count() as u32;
            if got < req.threshold {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: format!(
                        "role '{}' has {} of {} required signatures",
                        req.role, got, req.threshold
                    ),
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

    fn ctx<'a>(action: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(action)
    }

    fn req(role: &str, threshold: u32) -> SignatureRequirement {
        SignatureRequirement {
            role: role.to_string(),
            threshold,
        }
    }

    #[test]
    fn allows_when_threshold_met() {
        let c = SignatureCheck::from_required(vec![req("approver", 1)]);
        let a = Action {
            signatures: vec!["approver".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_below_threshold() {
        let c = SignatureCheck::from_required(vec![req("clinician", 2)]);
        let a = Action {
            signatures: vec!["clinician".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn multiple_roles_all_must_pass() {
        let c =
            SignatureCheck::from_required(vec![req("partner", 1), req("compliance", 1)]);
        let a = Action {
            signatures: vec!["partner".into()],
            ..Default::default()
        };
        // missing compliance signature → deny.
        assert!(c.evaluate(&ctx(&a)).is_deny());

        let a2 = Action {
            signatures: vec!["partner".into(), "compliance".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a2)).is_allow());
    }

    #[test]
    fn empty_requirements_allow_always() {
        let c = SignatureCheck::from_required(vec![]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn wrong_role_does_not_count() {
        let c = SignatureCheck::from_required(vec![req("clinician", 1)]);
        let a = Action {
            signatures: vec!["assistant".into(), "intern".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
