//! Data-flow / taint-tracking invariant — fail-closed sentinel.
//!
//! Full taint tracking is not implemented. Selecting this invariant must not
//! silently grant permission: it denies until a real tracker supplies a
//! cryptographically bound result.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Unsupported check. Always denies instead of creating a policy bypass.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataFlowCheck;

impl DataFlowCheck {
    /// Construct the fail-closed sentinel.
    pub fn new() -> Self {
        tracing::warn!("data_flow taint tracking unavailable; invariant will deny");
        Self
    }
}

impl RuntimeCheck for DataFlowCheck {
    fn name(&self) -> &'static str {
        "data_flow"
    }

    fn evaluate(&self, _ctx: &EvaluationContext) -> Verdict {
        Verdict::Deny {
            check: self.name().to_string(),
            reason:
                "data-flow tracking is not implemented; refusing to treat an unknown flow as safe"
                    .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;

    #[test]
    fn unsupported_tracker_denies() {
        let action = Action::default();
        assert!(DataFlowCheck::new()
            .evaluate(&EvaluationContext::with_defaults(&action))
            .is_deny());
    }
}
