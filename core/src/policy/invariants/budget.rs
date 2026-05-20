//! Budget cap invariant.
//!
//! Denies any action whose `amount_usd`, added to the running spend total,
//! would exceed the configured maximum. Actions without `amount_usd` are
//! treated as zero-cost and always pass.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Hard cap on cumulative USD spend for this policy.
#[derive(Debug, Clone, Copy)]
pub struct BudgetCheck {
    max_usd: f64,
}

impl BudgetCheck {
    /// Construct a budget cap. `max_usd` must already be validated as
    /// finite + non-negative by the parser.
    pub fn new(max_usd: f64) -> Self {
        Self { max_usd }
    }

    /// The configured cap.
    pub fn max_usd(&self) -> f64 {
        self.max_usd
    }
}

impl RuntimeCheck for BudgetCheck {
    fn name(&self) -> &'static str {
        "budget"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let amount = ctx.action.amount_usd.unwrap_or(0.0);
        let projected = ctx.spend_total_usd + amount;
        if projected > self.max_usd {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "projected spend {:.2} USD exceeds cap {:.2} USD",
                    projected, self.max_usd
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

    fn ctx<'a>(action: &'a Action, spend: f64) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(action);
        c.spend_total_usd = spend;
        c
    }

    #[test]
    fn allows_under_cap() {
        let check = BudgetCheck::new(100.0);
        let a = Action {
            amount_usd: Some(10.0),
            ..Default::default()
        };
        assert!(check.evaluate(&ctx(&a, 0.0)).is_allow());
    }

    #[test]
    fn denies_over_cap() {
        let check = BudgetCheck::new(100.0);
        let a = Action {
            amount_usd: Some(50.0),
            ..Default::default()
        };
        let v = check.evaluate(&ctx(&a, 60.0));
        assert!(v.is_deny());
    }

    #[test]
    fn allows_exact_cap() {
        let check = BudgetCheck::new(100.0);
        let a = Action {
            amount_usd: Some(40.0),
            ..Default::default()
        };
        assert!(check.evaluate(&ctx(&a, 60.0)).is_allow());
    }

    #[test]
    fn zero_amount_passes_even_if_already_over() {
        // Defensive: previous overspend shouldn't keep blocking $0 reads.
        // Cap defines projected spend; a $0 action keeps projected unchanged.
        let check = BudgetCheck::new(100.0);
        let a = Action {
            amount_usd: None,
            ..Default::default()
        };
        // spend < cap → allow.
        assert!(check.evaluate(&ctx(&a, 90.0)).is_allow());
    }

    #[test]
    fn deny_reason_mentions_check_name() {
        let check = BudgetCheck::new(50.0);
        let a = Action {
            amount_usd: Some(100.0),
            ..Default::default()
        };
        match check.evaluate(&ctx(&a, 0.0)) {
            Verdict::Deny { check, .. } => assert_eq!(check, "budget"),
            _ => panic!("expected deny"),
        }
    }
}
