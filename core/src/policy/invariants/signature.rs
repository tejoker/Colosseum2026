//! M-of-N signature invariant.
//!
//! For each `(role, threshold)` requirement, the action's `signatures`
//! vector must contain at least `threshold` **distinct** entries that bear
//! that role. An entry bears a role when it is exactly the role name
//! (`"clinician"`) or carries an explicit signer identity in `role:identity`
//! form (`"clinician:alice"`).
//!
//! Distinctness is the security property: an `M`-of-`N` requirement must not
//! be satisfiable by the same signature string repeated. `2-of-2 clinician`
//! is therefore met by `["clinician:alice", "clinician:bob"]` but **not** by
//! `["clinician", "clinician"]` (which collapses to one distinct signer). The
//! `threshold` field is documented as a distinct-signature count, so this
//! enforces the documented contract.

use std::collections::HashSet;

use crate::policy::ast::SignatureRequirement;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// `true` when `sig` bears `role` — either an exact role match or an
/// identity-qualified `role:identity` entry.
pub(crate) fn signature_bears_role(sig: &str, role: &str) -> bool {
    sig == role
        || sig
            .strip_prefix(role)
            .is_some_and(|rest| rest.starts_with(':') && rest.len() > 1)
}

/// Count the **distinct** signature entries in `signatures` that bear `role`.
/// Repeated identical entries count once, so the result is the number of
/// independent signers, not the number of signature strings.
pub(crate) fn distinct_role_signatures(signatures: &[String], role: &str) -> u32 {
    let mut seen: HashSet<&str> = HashSet::new();
    for s in signatures {
        if signature_bears_role(s, role) {
            seen.insert(s.as_str());
        }
    }
    seen.len() as u32
}

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
            let got = distinct_role_signatures(&ctx.action.signatures, &req.role);
            if got < req.threshold {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: format!(
                        "role '{}' has {} of {} required distinct signatures",
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
    fn duplicate_role_strings_do_not_satisfy_m_of_n() {
        // The classic bug: one actor stuffs the role string twice.
        let c = SignatureCheck::from_required(vec![req("clinician", 2)]);
        let a = Action {
            signatures: vec!["clinician".into(), "clinician".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny(), "duplicates must not meet 2-of-2");
    }

    #[test]
    fn distinct_identities_satisfy_m_of_n() {
        let c = SignatureCheck::from_required(vec![req("clinician", 2)]);
        let a = Action {
            signatures: vec!["clinician:alice".into(), "clinician:bob".into()],
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow(), "two distinct signers meet 2-of-2");
    }

    #[test]
    fn identity_qualified_entry_still_bears_role_for_threshold_one() {
        let c = SignatureCheck::from_required(vec![req("partner", 1)]);
        let a = Action {
            signatures: vec!["partner:jane".into()],
            ..Default::default()
        };
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
