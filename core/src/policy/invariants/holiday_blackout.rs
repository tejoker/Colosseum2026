//! Holiday-blackout invariant.
//!
//! Denies any action on a declared blackout date. Reads
//! `binding.holiday_blackout_dates` (a list of `YYYY-MM-DD` strings) and
//! `ctx.now_date_yyyy_mm_dd`. Use this for hard freezes on public
//! holidays, year-end change moratoria, etc.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Set of blackout dates in `YYYY-MM-DD` form.
#[derive(Debug, Clone)]
pub struct HolidayBlackoutCheck {
    dates: HashSet<String>,
}

impl HolidayBlackoutCheck {
    /// Build from a list of dates. Caller is responsible for validating
    /// the date strings — the parser does a `YYYY-MM-DD` shape check
    /// upstream.
    pub fn new(dates: Vec<String>) -> Self {
        Self {
            dates: dates.into_iter().collect(),
        }
    }
}

impl RuntimeCheck for HolidayBlackoutCheck {
    fn name(&self) -> &'static str {
        "holiday_blackout"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        if ctx.now_date_yyyy_mm_dd.is_empty() {
            // No date supplied — treat as non-blackout. Defensive: if a
            // caller forgets to populate the field we don't want
            // false-positive denies.
            return Verdict::Allow;
        }
        if self.dates.contains(&ctx.now_date_yyyy_mm_dd) {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("{} is on holiday blackout", ctx.now_date_yyyy_mm_dd),
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

    fn ctx<'a>(a: &'a Action, date: &str) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.now_date_yyyy_mm_dd = date.to_string();
        c
    }

    #[test]
    fn denies_blackout_date() {
        let c = HolidayBlackoutCheck::new(vec!["2026-12-25".into()]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "2026-12-25")).is_deny());
    }

    #[test]
    fn allows_other_dates() {
        let c = HolidayBlackoutCheck::new(vec!["2026-12-25".into()]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "2026-12-26")).is_allow());
    }

    #[test]
    fn empty_blackout_allows_everything() {
        let c = HolidayBlackoutCheck::new(vec![]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "2026-12-25")).is_allow());
    }

    #[test]
    fn missing_date_allows() {
        let c = HolidayBlackoutCheck::new(vec!["2026-12-25".into()]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, "")).is_allow());
    }
}
