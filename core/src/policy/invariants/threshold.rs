//! Generic numeric-threshold invariant.
//!
//! Currently exposes one constructor — `delegation_depth(max_depth)` —
//! which denies actions whose `delegation_depth` exceeds the configured
//! cap. Kept as a flexible generic so future numeric caps (sub-agent
//! count, message-size limits, …) reuse the same machinery.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Discriminator for which numeric field the threshold applies to.
#[derive(Debug, Clone, Copy)]
enum ThresholdKind {
    DelegationDepth,
}

impl ThresholdKind {
    fn name(self) -> &'static str {
        match self {
            ThresholdKind::DelegationDepth => "delegation_depth",
        }
    }
}

/// Generic numeric upper bound on a single action field.
#[derive(Debug, Clone, Copy)]
pub struct ThresholdCheck {
    kind: ThresholdKind,
    max: u32,
}

impl ThresholdCheck {
    /// Cap on `Action::delegation_depth`. Action denied if depth > max.
    pub fn delegation_depth(max: u32) -> Self {
        Self {
            kind: ThresholdKind::DelegationDepth,
            max,
        }
    }
}

impl RuntimeCheck for ThresholdCheck {
    fn name(&self) -> &'static str {
        self.kind.name()
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let value = match self.kind {
            ThresholdKind::DelegationDepth => ctx.action.delegation_depth,
        };
        if value > self.max {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("{} = {} exceeds max {}", self.name(), value, self.max),
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

    #[test]
    fn allows_at_exact_max() {
        let c = ThresholdCheck::delegation_depth(2);
        let a = Action {
            delegation_depth: 2,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_above_max() {
        let c = ThresholdCheck::delegation_depth(1);
        let a = Action {
            delegation_depth: 2,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn zero_max_blocks_any_delegation() {
        let c = ThresholdCheck::delegation_depth(0);
        let a = Action {
            delegation_depth: 1,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());

        let root = Action {
            delegation_depth: 0,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&root)).is_allow());
    }

    #[test]
    fn name_reflects_kind() {
        let c = ThresholdCheck::delegation_depth(1);
        assert_eq!(c.name(), "delegation_depth");
    }
}
