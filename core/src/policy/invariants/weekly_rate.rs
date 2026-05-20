//! Weekly rate-limit invariant.
//!
//! Like [`RateCheck`](super::RateCheck) but operates over a rolling 7-day
//! window. Reads `binding.weekly_rate.requests_per_week` and uses
//! `ctx.weekly_call_timestamps` (callers must supply timestamps within
//! the last 7 days; older ones are filtered out at evaluation time).
//!
//! Useful for "no more than 1000 emails per week per agent" type limits
//! that can't be expressed cleanly with a per-minute rate.

use super::{EvaluationContext, RuntimeCheck, Verdict};

const WINDOW_SECS: i64 = 7 * 24 * 60 * 60;

/// Rolling 7-day request-rate cap.
#[derive(Debug, Clone, Copy)]
pub struct WeeklyRateCheck {
    requests_per_week: u32,
}

impl WeeklyRateCheck {
    /// Build from the configured weekly cap. Parser ensures > 0.
    pub fn new(requests_per_week: u32) -> Self {
        Self { requests_per_week }
    }

    /// The configured cap.
    pub fn limit(&self) -> u32 {
        self.requests_per_week
    }
}

impl RuntimeCheck for WeeklyRateCheck {
    fn name(&self) -> &'static str {
        "weekly_rate"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let lower = ctx.now_epoch.saturating_sub(WINDOW_SECS);
        let count: u32 = ctx
            .weekly_call_timestamps
            .iter()
            .filter(|&&t| t > lower && t <= ctx.now_epoch)
            .count() as u32;
        if count >= self.requests_per_week {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "{} calls in last 7 days reached weekly limit {}",
                    count, self.requests_per_week
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

    fn ctx<'a>(a: &'a Action, ts: &'a [i64], now: i64) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.weekly_call_timestamps = ts;
        c.now_epoch = now;
        c
    }

    #[test]
    fn allows_under_limit() {
        let c = WeeklyRateCheck::new(100);
        let a = Action::default();
        let ts = [1_000_000, 1_500_000, 1_700_000];
        assert!(c.evaluate(&ctx(&a, &ts, 1_700_001)).is_allow());
    }

    #[test]
    fn denies_at_limit() {
        let c = WeeklyRateCheck::new(2);
        let a = Action::default();
        let now = 1_700_000;
        let ts = [now - 100, now - 50];
        assert!(c.evaluate(&ctx(&a, &ts, now)).is_deny());
    }

    #[test]
    fn ignores_outside_window() {
        let c = WeeklyRateCheck::new(2);
        let a = Action::default();
        let now = 1_700_000;
        let week_ago = now - WINDOW_SECS;
        // Two old (before window) + one fresh → count=1 → allow.
        let ts = [week_ago - 10, week_ago - 5, now - 1];
        assert!(c.evaluate(&ctx(&a, &ts, now)).is_allow());
    }

    #[test]
    fn empty_history_allows() {
        let c = WeeklyRateCheck::new(1);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, &[], 1_700_000)).is_allow());
    }
}
