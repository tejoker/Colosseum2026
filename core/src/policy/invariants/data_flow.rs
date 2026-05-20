//! Data-flow / taint-tracking invariant — **stub**.
//!
//! Sprint 2 ships this as a placeholder so the compiler interface is
//! stable. Full taint tracking (tracking PII reads → outputs through
//! function call graphs) is deferred to Sprint 6+.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Placeholder check. Always allows; warns once at construction.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataFlowCheck;

impl DataFlowCheck {
    /// Construct a stub data-flow check.
    pub fn new() -> Self {
        tracing::warn!("data_flow taint tracking deferred to S6+");
        Self
    }
}

impl RuntimeCheck for DataFlowCheck {
    fn name(&self) -> &'static str {
        "data_flow"
    }

    fn evaluate(&self, _ctx: &EvaluationContext) -> Verdict {
        Verdict::Allow
    }
}
