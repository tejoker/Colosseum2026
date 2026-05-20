//! Per-action cap invariant.
//!
//! Hard limit on the size of any single action. Reads
//! `binding.max_single_action_usd` and the action's `amount_usd`. Denies
//! whenever a single action exceeds the cap, regardless of cumulative
//! spend. Useful for "no single payment > $1000 without escalation".

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Maximum dollar value of any single action.
#[derive(Debug, Clone, Copy)]
pub struct PerActionCapCheck {
    max_single_action_usd: f64,
}

impl PerActionCapCheck {
    /// Build from a finite, non-negative cap (parser validates).
    pub fn new(max_single_action_usd: f64) -> Self {
        Self {
            max_single_action_usd,
        }
    }
}

impl RuntimeCheck for PerActionCapCheck {
    fn name(&self) -> &'static str {
        "per_action_cap"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let amount = ctx.action.amount_usd.unwrap_or(0.0);
        if amount > self.max_single_action_usd {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "single action amount {:.2} USD exceeds per-action cap {:.2} USD",
                    amount, self.max_single_action_usd
                ),
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
    fn allows_under_cap() {
        let c = PerActionCapCheck::new(1000.0);
        let a = Action {
            amount_usd: Some(500.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_over_cap() {
        let c = PerActionCapCheck::new(1000.0);
        let a = Action {
            amount_usd: Some(1001.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_exact_cap() {
        let c = PerActionCapCheck::new(1000.0);
        let a = Action {
            amount_usd: Some(1000.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn no_amount_allows() {
        let c = PerActionCapCheck::new(1000.0);
        let a = Action {
            amount_usd: None,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }
}
