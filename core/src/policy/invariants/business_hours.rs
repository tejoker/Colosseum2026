//! Business-hours invariant.
//!
//! Per-weekday wall-clock windows — finer than `TimeCheck`, which applies
//! a single uniform window every day. Reads `binding.business_hours` and
//! `ctx.now_weekday` + `ctx.now_tz_hhmm`. Missing weekday in the
//! configured map means the agent is fully blocked that day (e.g. no
//! action on weekends).
//!
//! Weekday encoding: 0=Sunday, 1=Monday, …, 6=Saturday. Matches the
//! standard `chrono::Datelike::num_days_from_sunday` convention used by
//! callers.

use std::collections::HashMap;

use crate::policy::ast::BusinessHours;
use crate::policy::types::{validate_hhmm, PolicyParseError};

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Per-weekday business-hours windows.
#[derive(Debug, Clone)]
pub struct BusinessHoursCheck {
    /// weekday → (start_hhmm, end_hhmm). Both bounds inclusive.
    windows: HashMap<u8, (String, String)>,
    /// Stored only for diagnostics — caller does the tz conversion.
    tz: String,
}

impl BusinessHoursCheck {
    /// Build from the parsed config. Re-validates every `HH:MM` string
    /// (defence in depth — the parser already validated them).
    pub fn from_config(bh: &BusinessHours) -> Result<Self, PolicyParseError> {
        let mut windows = HashMap::new();
        for (wd, [start, end]) in &bh.weekday_windows {
            validate_hhmm(start)?;
            validate_hhmm(end)?;
            windows.insert(*wd, (start.clone(), end.clone()));
        }
        Ok(Self {
            windows,
            tz: bh.timezone.clone(),
        })
    }

    fn in_window(start: &str, end: &str, hhmm: &str) -> bool {
        if start <= end {
            hhmm >= start && hhmm <= end
        } else {
            // Overnight: [start, 23:59] ∪ [00:00, end].
            hhmm >= start || hhmm <= end
        }
    }
}

impl RuntimeCheck for BusinessHoursCheck {
    fn name(&self) -> &'static str {
        "business_hours"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        match self.windows.get(&ctx.now_weekday) {
            Some((s, e)) => {
                if Self::in_window(s, e, &ctx.now_tz_hhmm) {
                    Verdict::Allow
                } else {
                    Verdict::Deny {
                        check: self.name().to_string(),
                        reason: format!(
                            "current time {} ({}) outside business hours [{}, {}] on weekday {}",
                            ctx.now_tz_hhmm, self.tz, s, e, ctx.now_weekday
                        ),
                    }
                }
            }
            None => Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "weekday {} not configured as a business day",
                    ctx.now_weekday
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;
    use std::collections::BTreeMap;

    fn ctx<'a>(a: &'a Action, weekday: u8, hhmm: &str) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.now_weekday = weekday;
        c.now_tz_hhmm = hhmm.to_string();
        c
    }

    fn check_mon_fri() -> BusinessHoursCheck {
        let mut windows = BTreeMap::new();
        for wd in 1..=5u8 {
            windows.insert(wd, ["09:00".to_string(), "18:00".to_string()]);
        }
        BusinessHoursCheck::from_config(&BusinessHours {
            weekday_windows: windows,
            timezone: "Europe/Paris".into(),
        })
        .unwrap()
    }

    #[test]
    fn allows_monday_noon() {
        let c = check_mon_fri();
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 1, "12:00")).is_allow());
    }

    #[test]
    fn denies_saturday() {
        let c = check_mon_fri();
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 6, "12:00")).is_deny());
    }

    #[test]
    fn denies_sunday() {
        let c = check_mon_fri();
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 0, "12:00")).is_deny());
    }

    #[test]
    fn denies_monday_before_open() {
        let c = check_mon_fri();
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 1, "08:00")).is_deny());
    }

    #[test]
    fn allows_friday_exact_close() {
        let c = check_mon_fri();
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 5, "18:00")).is_allow());
    }
}
