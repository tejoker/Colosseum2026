//! Rate-limit invariant.
//!
//! Denies the action if the number of recent timestamps in the past 60s
//! (relative to `ctx.now_epoch`) is at or above `requests_per_minute`.
//! The caller is responsible for trimming `recent_call_timestamps` to a
//! reasonable bound — the check itself scans the slice linearly.

use super::{EvaluationContext, RuntimeCheck, Verdict};

const WINDOW_SECS: i64 = 60;

/// Token-bucket-style rate limit (requests per minute).
#[derive(Debug, Clone, Copy)]
pub struct RateCheck {
    requests_per_minute: u32,
}

impl RateCheck {
    /// Construct a rate check. Caller-supplied `requests_per_minute`
    /// must be > 0 (the parser enforces this; we don't re-validate).
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
        }
    }

    /// Configured cap.
    pub fn limit(&self) -> u32 {
        self.requests_per_minute
    }
}

impl RuntimeCheck for RateCheck {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let lower = ctx.now_epoch.saturating_sub(WINDOW_SECS);
        let count: u32 = ctx
            .recent_call_timestamps
            .iter()
            .filter(|&&t| t > lower && t <= ctx.now_epoch)
            .count() as u32;
        if count >= self.requests_per_minute {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "{} calls in last 60s reached limit {}",
                    count, self.requests_per_minute
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

    fn ctx<'a>(action: &'a Action, ts: &'a [i64], now: i64) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(action);
        c.recent_call_timestamps = ts;
        c.now_epoch = now;
        c
    }

    #[test]
    fn allows_under_limit() {
        let c = RateCheck::new(5);
        let a = Action::default();
        let ts = [990, 995, 1000];
        assert!(c.evaluate(&ctx(&a, &ts, 1000)).is_allow());
    }

    #[test]
    fn denies_at_limit() {
        let c = RateCheck::new(3);
        let a = Action::default();
        let ts = [990, 995, 1000];
        assert!(c.evaluate(&ctx(&a, &ts, 1000)).is_deny());
    }

    #[test]
    fn old_calls_outside_window_ignored() {
        let c = RateCheck::new(2);
        let a = Action::default();
        // Two old calls (>60s ago) + one fresh one → count=1 → allow.
        let ts = [500, 600, 990];
        assert!(c.evaluate(&ctx(&a, &ts, 1000)).is_allow());
    }

    #[test]
    fn empty_history_allows() {
        let c = RateCheck::new(1);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, &[], 1000)).is_allow());
    }

    #[test]
    fn future_timestamps_ignored() {
        // Defensive: clocks can skew. Anything > now is ignored.
        let c = RateCheck::new(2);
        let a = Action::default();
        let ts = [995, 1001, 1002];
        assert!(c.evaluate(&ctx(&a, &ts, 1000)).is_allow());
    }
}
