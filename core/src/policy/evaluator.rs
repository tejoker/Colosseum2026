//! Policy evaluator — runs the compiled checks against an action.
//!
//! Evaluation is fail-fast: the first deny short-circuits and is
//! returned. `evaluate_with_trace` runs every check and returns the
//! per-check verdicts alongside the overall outcome — handy for the
//! dashboard's policy debugger.

use super::compiler::CompiledPolicy;
use super::invariants::{EvaluationContext, Verdict};

/// Run all compiled checks against `ctx`. Returns [`Verdict::Allow`]
/// only if every check allows.
pub fn evaluate(compiled: &CompiledPolicy, ctx: &EvaluationContext) -> Verdict {
    for check in &compiled.checks {
        match check.evaluate(ctx) {
            Verdict::Allow => continue,
            deny @ Verdict::Deny { .. } => return deny,
        }
    }
    Verdict::Allow
}

/// Run every check (no short-circuit) and return per-check verdicts.
///
/// Useful for the dashboard's "why did this deny?" view — shows whether
/// other checks would also have denied, not just the first one.
pub fn evaluate_with_trace(
    compiled: &CompiledPolicy,
    ctx: &EvaluationContext,
) -> (Verdict, Vec<(String, Verdict)>) {
    let mut trace: Vec<(String, Verdict)> = Vec::with_capacity(compiled.checks.len());
    let mut overall = Verdict::Allow;
    for check in &compiled.checks {
        let v = check.evaluate(ctx);
        if let Verdict::Deny { .. } = &v {
            if overall.is_allow() {
                overall = v.clone();
            }
        }
        trace.push((check.name().to_string(), v));
    }
    (overall, trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compiler::compile;
    use crate::policy::invariants::Action;
    use crate::policy::parser::parse;

    const FX_BANKING: &str =
        include_str!("../../../schemas/fixtures/policy_banking_payment_agent.yaml");

    fn ctx<'a>(a: &'a Action, hhmm: &str) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.now_tz_hhmm = hhmm.to_string();
        c
    }

    #[test]
    fn banking_policy_allows_in_window_under_budget() {
        let c = compile(parse(FX_BANKING).unwrap()).unwrap();
        let mut a = Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(100.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into()],
            ..Default::default()
        };
        // Sprint 3: banking fixture now requires a sanctioned currency.
        a.metadata
            .insert("currency".into(), serde_json::json!("EUR"));
        let mut ctx0 = ctx(&a, "12:00");
        // Monday-ish weekday so business_hours check passes.
        ctx0.now_weekday = 1;
        assert_eq!(evaluate(&c, &ctx0), Verdict::Allow);
    }

    #[test]
    fn banking_policy_denies_outside_time_window() {
        let c = compile(parse(FX_BANKING).unwrap()).unwrap();
        let a = Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(100.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into()],
            ..Default::default()
        };
        let v = evaluate(&c, &ctx(&a, "22:00"));
        assert!(v.is_deny());
    }

    #[test]
    fn trace_records_every_check() {
        let c = compile(parse(FX_BANKING).unwrap()).unwrap();
        let a = Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(100.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into()],
            ..Default::default()
        };
        let (_, trace) = evaluate_with_trace(&c, &ctx(&a, "12:00"));
        assert_eq!(trace.len(), c.checks.len());
    }
}
