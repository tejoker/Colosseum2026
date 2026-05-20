//! Cooldown invariant.
//!
//! Enforces a minimum time gap between consecutive actions. Reads
//! `binding.cooldown_seconds` and `ctx.last_action_at`. Denies if the
//! gap from the previous action to `now` is below the configured
//! threshold. First action ever (no `last_action_at`) is always allowed.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Minimum-gap (seconds) between actions.
#[derive(Debug, Clone, Copy)]
pub struct CooldownCheck {
    cooldown_seconds: u64,
}

impl CooldownCheck {
    /// Construct from a non-negative cooldown.
    pub fn new(cooldown_seconds: u64) -> Self {
        Self { cooldown_seconds }
    }
}

impl RuntimeCheck for CooldownCheck {
    fn name(&self) -> &'static str {
        "cooldown"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(last) = ctx.last_action_at else {
            return Verdict::Allow;
        };
        let gap = ctx.now_epoch.saturating_sub(last);
        if gap < self.cooldown_seconds as i64 {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!(
                    "only {gap}s since previous action; cooldown requires {}s",
                    self.cooldown_seconds
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

    fn ctx<'a>(a: &'a Action, now: i64, last: Option<i64>) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.now_epoch = now;
        c.last_action_at = last;
        c
    }

    #[test]
    fn allows_when_no_previous_action() {
        let c = CooldownCheck::new(60);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 1000, None)).is_allow());
    }

    #[test]
    fn denies_inside_cooldown() {
        let c = CooldownCheck::new(60);
        let a = Action::default();
        // 30s gap, requires 60s.
        assert!(c.evaluate(&ctx(&a, 1000, Some(970))).is_deny());
    }

    #[test]
    fn allows_after_cooldown() {
        let c = CooldownCheck::new(60);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 1100, Some(1000))).is_allow());
    }

    #[test]
    fn allows_exact_cooldown_boundary() {
        let c = CooldownCheck::new(60);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a, 1060, Some(1000))).is_allow());
    }
}
