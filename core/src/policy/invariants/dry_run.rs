//! Dry-run invariant.
//!
//! When `binding.dry_run: true` is set, every action is permitted by
//! this check regardless of all other denial signals — and we annotate
//! the verdict so the evaluator's trace records that the policy is in
//! dry-run mode. Useful for staging environments where operators want
//! to evaluate policies against real traffic before enforcement.
//!
//! Important: this check ALWAYS returns Allow. It never denies. Other
//! checks may still deny — the evaluator's `evaluate` function short
//! circuits on the first deny. For pure observability the calling code
//! should use `evaluate_with_trace` and treat all denies as warnings
//! when dry-run is on. The check exists so the dry-run state surfaces
//! in the trace.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Marker check. Always allows. Presence in the compiled check list
/// signals "this policy is in dry-run mode" to the caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct DryRunCheck;

impl DryRunCheck {
    /// Construct a dry-run marker.
    pub fn new() -> Self {
        Self
    }
}

impl RuntimeCheck for DryRunCheck {
    fn name(&self) -> &'static str {
        "dry_run"
    }

    fn evaluate(&self, _ctx: &EvaluationContext) -> Verdict {
        Verdict::Allow
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
    fn always_allows_default_action() {
        let a = Action::default();
        assert!(DryRunCheck::new().evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn always_allows_with_amount() {
        let a = Action {
            amount_usd: Some(1_000_000.0),
            ..Default::default()
        };
        assert!(DryRunCheck::new().evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn name_is_dry_run() {
        assert_eq!(DryRunCheck::new().name(), "dry_run");
    }
}
