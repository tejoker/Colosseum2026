//! Time-window invariant.
//!
//! Denies the action if `ctx.now_tz_hhmm` falls outside the configured
//! [start, end] window. The caller is responsible for converting the
//! wall clock to the policy's timezone and formatting it as `HH:MM`
//! before populating the evaluation context.
//!
//! Both same-day windows (`09:00`..=`18:00`) and wrap-around windows
//! (`22:00`..=`06:00`) are supported — the latter denotes an overnight
//! shift.

use crate::policy::ast::TimeWindow;
use crate::policy::types::{validate_hhmm, PolicyParseError};

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Configured wall-clock window. Both bounds inclusive.
#[derive(Debug, Clone)]
pub struct TimeCheck {
    start: String,
    end: String,
    /// IANA timezone — stored only for diagnostics; the caller does the
    /// actual timezone conversion before calling `evaluate`.
    tz: String,
}

impl TimeCheck {
    /// Build from a parsed [`TimeWindow`]. Re-validates HH:MM defensively
    /// even though the parser already validated them.
    pub fn from_window(tw: &TimeWindow) -> Result<Self, PolicyParseError> {
        validate_hhmm(&tw.start)?;
        validate_hhmm(&tw.end)?;
        Ok(Self {
            start: tw.start.clone(),
            end: tw.end.clone(),
            tz: tw.timezone.clone(),
        })
    }

    /// `true` if `hhmm` falls within `[start, end]`. Handles wrap-around
    /// windows (start > end) as an overnight shift.
    fn in_window(start: &str, end: &str, hhmm: &str) -> bool {
        if start <= end {
            hhmm >= start && hhmm <= end
        } else {
            // Overnight: window = [start, 23:59] ∪ [00:00, end].
            hhmm >= start || hhmm <= end
        }
    }
}

impl RuntimeCheck for TimeCheck {
    fn name(&self) -> &'static str {
        "time_window"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        if Self::in_window(&self.start, &self.end, &ctx.now_tz_hhmm) {
            Verdict::Allow
        } else {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "current time {} ({}) outside window [{}, {}]",
                    ctx.now_tz_hhmm, self.tz, self.start, self.end
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;

    fn ctx<'a>(action: &'a Action, hhmm: &str) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(action);
        c.now_tz_hhmm = hhmm.to_string();
        c
    }

    fn check(start: &str, end: &str) -> TimeCheck {
        TimeCheck::from_window(&TimeWindow {
            start: start.into(),
            end: end.into(),
            timezone: "UTC".into(),
        })
        .unwrap()
    }

    #[test]
    fn allows_inside_window() {
        let c = check("09:00", "18:00");
        let a = Action::default();
        for hhmm in ["09:00", "12:34", "18:00"] {
            assert!(c.evaluate(&ctx(&a, hhmm)).is_allow(), "{hhmm}");
        }
    }

    #[test]
    fn denies_before_start() {
        let c = check("09:00", "18:00");
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "08:59")).is_deny());
    }

    #[test]
    fn denies_after_end() {
        let c = check("09:00", "18:00");
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "18:01")).is_deny());
    }

    #[test]
    fn wrap_around_window_allows_overnight() {
        let c = check("22:00", "06:00");
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "23:30")).is_allow());
        assert!(c.evaluate(&ctx(&a, "05:00")).is_allow());
        assert!(c.evaluate(&ctx(&a, "12:00")).is_deny());
    }

    #[test]
    fn deny_message_mentions_tz() {
        let c = check("09:00", "18:00");
        let a = Action::default();
        match c.evaluate(&ctx(&a, "07:00")) {
            Verdict::Deny { reason, .. } => assert!(reason.contains("UTC")),
            _ => panic!("expected deny"),
        }
    }
}
