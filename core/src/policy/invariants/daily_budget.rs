//! Daily budget invariant.
//!
//! Separate daily ceiling on top of the lifetime `BudgetCheck`. Reads the
//! caller-provided `ctx.daily_spend_usd` (which is the running 24h spend
//! the caller looks up from the ledger) and the action's `amount_usd`.
//! Denies any action whose projected daily spend would exceed
//! `binding.daily_budget_usd`. Non-monetary actions are zero-cost and
//! always pass.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Daily-spend cap (USD).
#[derive(Debug, Clone, Copy)]
pub struct DailyBudgetCheck {
    daily_cap_usd: f64,
}

impl DailyBudgetCheck {
    /// Construct from a positive cap. Parser-side validation ensures the
    /// value is finite + non-negative.
    pub fn new(daily_cap_usd: f64) -> Self {
        Self { daily_cap_usd }
    }

    /// The configured cap.
    pub fn cap(&self) -> f64 {
        self.daily_cap_usd
    }
}

impl RuntimeCheck for DailyBudgetCheck {
    fn name(&self) -> &'static str {
        "daily_budget"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let amount = ctx.action.amount_usd.unwrap_or(0.0);
        let projected = ctx.daily_spend_usd + amount;
        if projected > self.daily_cap_usd {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "projected daily spend {:.2} USD exceeds daily cap {:.2} USD",
                    projected, self.daily_cap_usd
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

    fn ctx<'a>(a: &'a Action, daily: f64) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.daily_spend_usd = daily;
        c
    }

    #[test]
    fn allows_under_daily_cap() {
        let c = DailyBudgetCheck::new(500.0);
        let a = Action {
            amount_usd: Some(50.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a, 100.0)).is_allow());
    }

    #[test]
    fn denies_over_daily_cap() {
        let c = DailyBudgetCheck::new(500.0);
        let a = Action {
            amount_usd: Some(450.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a, 100.0)).is_deny());
    }

    #[test]
    fn allows_exact_daily_cap() {
        let c = DailyBudgetCheck::new(500.0);
        let a = Action {
            amount_usd: Some(400.0),
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a, 100.0)).is_allow());
    }

    #[test]
    fn no_amount_always_passes() {
        let c = DailyBudgetCheck::new(10.0);
        let a = Action {
            amount_usd: None,
            ..Default::default()
        };
        assert!(c.evaluate(&ctx(&a, 5.0)).is_allow());
    }
}
