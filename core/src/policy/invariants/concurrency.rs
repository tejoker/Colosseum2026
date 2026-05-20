//! Concurrency invariant.
//!
//! Denies any action that would exceed the configured maximum number of
//! concurrent in-flight actions. Reads `binding.max_concurrent` and the
//! caller-provided `ctx.in_flight_actions`. The caller is responsible
//! for tracking the in-flight count (typically from a Redis counter or
//! Postgres `WHERE state='running'` query) before invoking the
//! evaluator.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Hard cap on simultaneous in-flight actions.
#[derive(Debug, Clone, Copy)]
pub struct ConcurrencyCheck {
    max_concurrent: u32,
}

impl ConcurrencyCheck {
    /// Build from the configured cap. Cap of 0 effectively denies
    /// everything; the parser should warn on that combo but doesn't
    /// reject it (sometimes useful for a kill switch).
    pub fn new(max_concurrent: u32) -> Self {
        Self { max_concurrent }
    }
}

impl RuntimeCheck for ConcurrencyCheck {
    fn name(&self) -> &'static str {
        "concurrency"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        if ctx.in_flight_actions >= self.max_concurrent {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "{} in-flight actions reached concurrency cap {}",
                    ctx.in_flight_actions, self.max_concurrent
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

    fn ctx<'a>(a: &'a Action, in_flight: u32) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.in_flight_actions = in_flight;
        c
    }

    #[test]
    fn allows_under_cap() {
        let c = ConcurrencyCheck::new(5);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 2)).is_allow());
    }

    #[test]
    fn denies_at_cap() {
        let c = ConcurrencyCheck::new(3);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 3)).is_deny());
    }

    #[test]
    fn denies_above_cap() {
        let c = ConcurrencyCheck::new(1);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 7)).is_deny());
    }

    #[test]
    fn zero_cap_denies_anything_running() {
        let c = ConcurrencyCheck::new(0);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 0)).is_deny());
    }
}
