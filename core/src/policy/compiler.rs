//! Policy compiler — turns a parsed [`Policy`] into a [`CompiledPolicy`]
//! containing a `Vec<Box<dyn RuntimeCheck>>` ready for the evaluator.
//!
//! Compilation never executes user policy logic; it only translates the
//! AST into runtime checks. Free-form `invariants:` strings are parsed by
//! the [`expressions`](super::expressions) module into [`ExpressionCheck`]s
//! that evaluate against the live [`EvaluationContext`].

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::ast::{Binding, Policy};
use super::expressions::{
    eval::{eval_predicate, EvalEnv},
    parser::{parse as parse_expr, Expr, ParseError},
};
use super::invariants::{
    AllowlistCheck, BudgetCheck, BusinessHoursCheck, ChainDepthCheck, ConcurrencyCheck,
    ContentTypeCheck, CooldownCheck, CurrencyAllowlistCheck, DailyBudgetCheck,
    DomainAllowlistCheck, DomainDenylistCheck, DryRunCheck, EvaluationContext, GeoRestrictionCheck,
    HolidayBlackoutCheck, LanguageAllowlistCheck, PayloadSizeCheck, PerActionCapCheck,
    PiiDetectionCheck, RateCheck, RecipientCountCheck, RuntimeCheck, ScopeCheck, SignatureCheck,
    ThresholdCheck, TimeCheck, ToolDenylistCheck, Verdict, VersionPinCheck, WeeklyRateCheck,
};
use super::types::PolicyParseError;

/// A policy compiled into runtime checks.
///
/// `raw` is preserved for serialisation back to YAML/JSON (e.g. for the
/// `GET /v1/policy/:id` endpoint). `policy_id` is content-addressed via
/// SHA-256 of canonical JSON serialisation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Server-assigned id of the form `pol_<32-hex>` (SHA-256/16 bytes).
    pub policy_id: String,
    /// Agent identifier — copied from the policy for fast lookup.
    pub agent: String,
    /// Compiled runtime checks, in declaration order.
    pub checks: Vec<Box<dyn RuntimeCheck>>,
    /// Original parsed policy, retained for serialisation.
    pub raw: Policy,
}

/// Errors that can occur during compilation.
#[derive(Debug, Clone, PartialEq)]
pub enum CompileError {
    /// `data_scope` had an internal inconsistency the parser missed.
    InvalidScope(String),
    /// `time_window` failed re-validation.
    InvalidTimeWindow(String),
    /// One of the free-form `invariants:` strings failed to parse.
    ///
    /// `line` is the 0-based index of the offending invariant in the
    /// `invariants:` list (proper YAML line numbers will land when the
    /// parser tracks source spans — out of scope here).
    InvariantParseError {
        /// Index into `policy.invariants`.
        line: usize,
        /// Human-readable parser error message.
        msg: String,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::InvalidScope(m) => write!(f, "invalid scope: {m}"),
            CompileError::InvalidTimeWindow(m) => write!(f, "invalid time window: {m}"),
            CompileError::InvariantParseError { line, msg } => {
                write!(f, "invariant #{line} parse error: {msg}")
            }
        }
    }
}

impl Error for CompileError {}

impl From<PolicyParseError> for CompileError {
    fn from(e: PolicyParseError) -> Self {
        // Map at the call sites that know the context. The blanket impl is
        // here as a safety net for parser-driven re-validation inside
        // `ScopeCheck::from_scope` / `TimeCheck::from_window`.
        CompileError::InvalidScope(e.to_string())
    }
}

/// Runtime check that evaluates a parsed expression against the live
/// context + action + a snapshot of the policy [`Binding`].
///
/// The binding snapshot is held via `Arc` so cloning the compiled policy
/// (for caching or hand-off across threads) stays cheap.
#[derive(Debug)]
pub struct ExpressionCheck {
    /// The original source string — retained for trace logs + deny reasons.
    pub src: String,
    /// The parsed expression AST.
    pub expr: Expr,
    /// Snapshot of the policy binding at compile time. Held via `Arc` so
    /// clones share storage.
    pub binding: Arc<Binding>,
}

impl ExpressionCheck {
    /// Construct an [`ExpressionCheck`] from a parsed expression + binding.
    pub fn new(src: String, expr: Expr, binding: Arc<Binding>) -> Self {
        Self { src, expr, binding }
    }
}

impl RuntimeCheck for ExpressionCheck {
    fn name(&self) -> &'static str {
        "invariant_expr"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let env = EvalEnv {
            action: ctx.action,
            ctx,
            binding: &self.binding,
            now_epoch: ctx.now_epoch,
        };
        match eval_predicate(&self.expr, &env) {
            Ok(true) => Verdict::Allow,
            Ok(false) => Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("invariant violated: {}", self.src),
            },
            Err(e) => Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("invariant evaluation error in `{}`: {}", self.src, e),
            },
        }
    }
}

/// Compile a parsed [`Policy`] into a [`CompiledPolicy`].
pub fn compile(policy: Policy) -> Result<CompiledPolicy, CompileError> {
    let mut checks: Vec<Box<dyn RuntimeCheck>> = Vec::new();

    if let Some(b) = policy.binding.max_budget_usd {
        checks.push(Box::new(BudgetCheck::new(b)));
    }
    if let Some(ref ds) = policy.binding.data_scope {
        let check =
            ScopeCheck::from_scope(ds).map_err(|e| CompileError::InvalidScope(e.to_string()))?;
        checks.push(Box::new(check));
    }
    if let Some(ref tools) = policy.binding.allowed_tools {
        checks.push(Box::new(AllowlistCheck::tools(tools.clone())));
    }
    if let Some(ref rl) = policy.binding.rate_limit {
        checks.push(Box::new(RateCheck::new(rl.requests_per_minute)));
    }
    if let Some(ref tw) = policy.binding.time_window {
        let check = TimeCheck::from_window(tw)
            .map_err(|e| CompileError::InvalidTimeWindow(e.to_string()))?;
        checks.push(Box::new(check));
    }
    if let Some(ref sigs) = policy.binding.required_signatures {
        checks.push(Box::new(SignatureCheck::from_required(sigs.clone())));
    }
    if let Some(ref d) = policy.binding.delegation {
        checks.push(Box::new(ThresholdCheck::delegation_depth(d.max_depth)));
    }

    // ─── Sprint 3 invariants ─────────────────────────────────────────────
    // Order chosen so cheap, common denials fire first (denylists before
    // allowlists where it matters) but every check still runs in
    // `evaluate_with_trace`. All fields are read from `policy.binding`
    // (the metadata bag stays free-form for operator-tooling tags).
    if let Some(ref domains) = policy.binding.domain_denylist {
        checks.push(Box::new(DomainDenylistCheck::new(domains.clone())));
    }
    if let Some(ref domains) = policy.binding.domain_allowlist {
        checks.push(Box::new(DomainAllowlistCheck::new(domains.clone())));
    }
    if let Some(ref tools) = policy.binding.tool_denylist {
        checks.push(Box::new(ToolDenylistCheck::tools(tools.clone())));
    }
    if let Some(cap) = policy.binding.daily_budget_usd {
        checks.push(Box::new(DailyBudgetCheck::new(cap)));
    }
    if let Some(cap) = policy.binding.max_single_action_usd {
        checks.push(Box::new(PerActionCapCheck::new(cap)));
    }
    if let Some(ref wr) = policy.binding.weekly_rate {
        checks.push(Box::new(WeeklyRateCheck::new(wr.requests_per_week)));
    }
    if let Some(n) = policy.binding.max_concurrent {
        checks.push(Box::new(ConcurrencyCheck::new(n)));
    }
    if let Some(s) = policy.binding.cooldown_seconds {
        checks.push(Box::new(CooldownCheck::new(s)));
    }
    if let Some(b) = policy.binding.max_payload_bytes {
        checks.push(Box::new(PayloadSizeCheck::new(b)));
    }
    if let Some(ref cts) = policy.binding.content_type_allowlist {
        checks.push(Box::new(ContentTypeCheck::new(cts.clone())));
    }
    if let Some(n) = policy.binding.max_recipients {
        checks.push(Box::new(RecipientCountCheck::new(n)));
    }
    if let Some(d) = policy.binding.max_chain_depth {
        checks.push(Box::new(ChainDepthCheck::new(d)));
    }
    if let Some(true) = policy.binding.pii_block {
        checks.push(Box::new(PiiDetectionCheck::new()));
    }
    if let Some(ref langs) = policy.binding.language_allowlist {
        checks.push(Box::new(LanguageAllowlistCheck::new(langs.clone())));
    }
    if let Some(ref ccys) = policy.binding.currency_allowlist {
        checks.push(Box::new(CurrencyAllowlistCheck::new(ccys.clone())));
    }
    // Geo: register if either allow OR deny list is non-empty.
    let geo_allow = policy
        .binding
        .geo_allow_countries
        .clone()
        .unwrap_or_default();
    let geo_deny = policy
        .binding
        .geo_deny_countries
        .clone()
        .unwrap_or_default();
    if !geo_allow.is_empty() || !geo_deny.is_empty() {
        checks.push(Box::new(GeoRestrictionCheck::new(geo_allow, geo_deny)));
    }
    if let Some(ref bh) = policy.binding.business_hours {
        let check = BusinessHoursCheck::from_config(bh)
            .map_err(|e| CompileError::InvalidTimeWindow(e.to_string()))?;
        checks.push(Box::new(check));
    }
    if let Some(ref dates) = policy.binding.holiday_blackout_dates {
        checks.push(Box::new(HolidayBlackoutCheck::new(dates.clone())));
    }
    if let Some(ref v) = policy.binding.pinned_version {
        checks.push(Box::new(VersionPinCheck::new(v.clone())));
    }
    if let Some(true) = policy.binding.dry_run {
        checks.push(Box::new(DryRunCheck::new()));
    }

    // Free-form invariant expressions — parse each one. A failure here is
    // fatal: the policy cannot be enforced if we don't understand its rules.
    let binding_arc = Arc::new(policy.binding.clone());
    for (i, src) in policy.invariants.iter().enumerate() {
        let expr = parse_expr(src).map_err(|e: ParseError| CompileError::InvariantParseError {
            line: i,
            msg: e.to_string(),
        })?;
        checks.push(Box::new(ExpressionCheck::new(
            src.clone(),
            expr,
            Arc::clone(&binding_arc),
        )));
    }

    let policy_id = hash_policy(&policy);
    Ok(CompiledPolicy {
        policy_id,
        agent: policy.agent.clone(),
        checks,
        raw: policy,
    })
}

/// Content-address a policy by hashing its canonical JSON serialisation.
pub fn hash_policy(p: &Policy) -> String {
    let canon = serde_json::to_string(p).expect("policy is always JSON-serialisable");
    let mut h = Sha256::new();
    h.update(canon.as_bytes());
    let digest = h.finalize();
    format!("pol_{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;
    use crate::policy::parser::parse;

    const FX_BANKING: &str =
        include_str!("../../../schemas/fixtures/policy_banking_payment_agent.yaml");
    const FX_MINIMAL: &str = include_str!("../../../schemas/fixtures/policy_minimal.yaml");
    const FX_HEALTHCARE: &str =
        include_str!("../../../schemas/fixtures/policy_healthcare_records.yaml");
    const FX_DEVTOOLS: &str =
        include_str!("../../../schemas/fixtures/policy_devtools_codegen.yaml");
    const FX_RESEARCH: &str =
        include_str!("../../../schemas/fixtures/policy_research_assistant.yaml");
    const FX_SUPPORT: &str =
        include_str!("../../../schemas/fixtures/policy_customer_support_chatbot.yaml");
    const FX_MARKETING: &str =
        include_str!("../../../schemas/fixtures/policy_marketing_content.yaml");
    const FX_LEGAL: &str = include_str!("../../../schemas/fixtures/policy_legal_review.yaml");
    const FX_ANALYST: &str = include_str!("../../../schemas/fixtures/policy_data_analyst.yaml");
    const FX_TREASURY: &str = include_str!("../../../schemas/fixtures/policy_treasury_ops.yaml");

    fn make_ctx<'a>(a: &'a Action, spend: f64) -> EvaluationContext<'a> {
        let mut c = EvaluationContext::with_defaults(a);
        c.spend_total_usd = spend;
        c.now_tz_hhmm = "12:00".to_string();
        c
    }

    #[test]
    fn compiles_banking_policy_with_all_checks() {
        let p = parse(FX_BANKING).expect("parse");
        let compiled = compile(p).expect("compile");
        let names: Vec<&str> = compiled.checks.iter().map(|c| c.name()).collect();
        assert!(names.contains(&"budget"));
        assert!(names.contains(&"scope"));
        assert!(names.contains(&"allowlist"));
        assert!(names.contains(&"rate_limit"));
        assert!(names.contains(&"time_window"));
        assert!(names.contains(&"signatures"));
        assert!(names.contains(&"delegation_depth"));
        // Banking fixture has 3 free-form invariants — all compiled.
        let exprs = names.iter().filter(|n| **n == "invariant_expr").count();
        assert_eq!(exprs, 3);
    }

    #[test]
    fn compiles_minimal_policy_with_one_invariant_check() {
        let p = parse(FX_MINIMAL).expect("parse");
        let compiled = compile(p).expect("compile");
        // Minimal fixture has no binding fields but does carry one
        // invariant: "spend_total <= 1" → 1 ExpressionCheck.
        assert_eq!(compiled.checks.len(), 1);
        assert_eq!(compiled.checks[0].name(), "invariant_expr");
        assert!(compiled.policy_id.starts_with("pol_"));
    }

    #[test]
    fn same_policy_yields_same_id() {
        let p1 = parse(FX_BANKING).expect("parse 1");
        let p2 = parse(FX_BANKING).expect("parse 2");
        let c1 = compile(p1).unwrap();
        let c2 = compile(p2).unwrap();
        assert_eq!(c1.policy_id, c2.policy_id);
    }

    #[test]
    fn different_policies_yield_different_ids() {
        let c1 = compile(parse(FX_BANKING).unwrap()).unwrap();
        let c2 = compile(parse(FX_MINIMAL).unwrap()).unwrap();
        assert_ne!(c1.policy_id, c2.policy_id);
    }

    #[test]
    fn invariant_parse_error_is_surfaced_with_line_index() {
        // Synthesise a policy with one bad invariant.
        let mut p = parse(FX_MINIMAL).unwrap();
        p.invariants.push("a == ".to_string()); // truncated → parse error
        let err = compile(p).unwrap_err();
        match err {
            CompileError::InvariantParseError { line, .. } => {
                // Original fixture has 1 invariant at index 0; ours is index 1.
                assert_eq!(line, 1);
            }
            other => panic!("expected InvariantParseError, got {other:?}"),
        }
    }

    // ----- End-to-end: each fixture's invariants compile + evaluate -----

    #[test]
    fn compile_with_expressions_banking_evaluates_under_budget() {
        let p = parse(FX_BANKING).unwrap();
        let c = compile(p).expect("banking compiles");
        // First invariant is `spend_total <= max_budget_usd`. Spend 100,
        // cap 5000 → ExpressionCheck allows.
        let a = Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(0.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into()],
            ..Default::default()
        };
        let ctx = make_ctx(&a, 100.0);
        // Run only the invariant_expr checks (others depend on time_window
        // / rate / scope and may produce unrelated denies depending on
        // setup; we exercise them in policy_evaluator.rs).
        for check in c.checks.iter().filter(|c| c.name() == "invariant_expr") {
            assert!(check.evaluate(&ctx).is_allow(), "{} denied", check.name());
        }
    }

    #[test]
    fn compile_with_expressions_minimal_denies_over_invariant_cap() {
        // Minimal fixture says `spend_total <= 1`. With spend=2 the
        // invariant must deny.
        let p = parse(FX_MINIMAL).unwrap();
        let c = compile(p).unwrap();
        let a = Action {
            action_id: "a1".into(),
            tool: "x".into(),
            ..Default::default()
        };
        let ctx = make_ctx(&a, 2.0);
        let v = c.checks[0].evaluate(&ctx);
        assert!(v.is_deny());
    }

    #[test]
    fn compile_with_expressions_treasury_compiles_three_invariants() {
        let c = compile(parse(FX_TREASURY).unwrap()).expect("treasury compiles");
        let exprs = c
            .checks
            .iter()
            .filter(|c| c.name() == "invariant_expr")
            .count();
        assert_eq!(exprs, 3);
    }

    #[test]
    fn compile_with_expressions_devtools_compiles() {
        let c = compile(parse(FX_DEVTOOLS).unwrap()).expect("devtools compiles");
        // Three invariants.
        let exprs = c
            .checks
            .iter()
            .filter(|c| c.name() == "invariant_expr")
            .count();
        assert_eq!(exprs, 3);
    }

    #[test]
    fn compile_with_expressions_healthcare_evaluates() {
        let p = parse(FX_HEALTHCARE).unwrap();
        let c = compile(p).expect("healthcare compiles");
        // First invariant: data_classification != 'restricted'.
        let a = Action {
            action_id: "a1".into(),
            tool: "read".into(),
            data_classification: Some("phi".into()),
            ..Default::default()
        };
        let ctx = make_ctx(&a, 0.0);
        // First expression check should allow (phi != restricted).
        let first_expr = c
            .checks
            .iter()
            .find(|c| c.name() == "invariant_expr")
            .unwrap();
        assert!(first_expr.evaluate(&ctx).is_allow());
    }

    // ----- Sprint 3: new binding fields compile into the expected check set -----

    #[test]
    fn banking_fixture_compiles_sprint3_checks() {
        let p = parse(FX_BANKING).expect("parse");
        let c = compile(p).expect("compile");
        let names: Vec<&str> = c.checks.iter().map(|c| c.name()).collect();
        // Sprint 2 checks still present.
        assert!(names.contains(&"budget"));
        // Sprint 3 additions.
        assert!(names.contains(&"daily_budget"));
        assert!(names.contains(&"per_action_cap"));
        assert!(names.contains(&"currency_allowlist"));
        assert!(names.contains(&"business_hours"));
        assert!(names.contains(&"holiday_blackout"));
    }

    #[test]
    fn healthcare_fixture_registers_pii_and_geo() {
        let c = compile(parse(FX_HEALTHCARE).unwrap()).expect("compile");
        let names: Vec<&str> = c.checks.iter().map(|c| c.name()).collect();
        assert!(names.contains(&"pii_detection"));
        assert!(names.contains(&"domain_allowlist"));
        assert!(names.contains(&"geo_restriction"));
    }

    #[test]
    fn devtools_fixture_registers_denylists_and_payload_cap() {
        let c = compile(parse(FX_DEVTOOLS).unwrap()).expect("compile");
        let names: Vec<&str> = c.checks.iter().map(|c| c.name()).collect();
        assert!(names.contains(&"tool_denylist"));
        assert!(names.contains(&"domain_denylist"));
        assert!(names.contains(&"payload_size"));
        assert!(names.contains(&"chain_depth"));
    }

    #[test]
    fn sprint3_worked_example_trace_shows_denial_chain() {
        // Build a policy exercising 6 new invariants then evaluate an
        // action that deliberately violates one of them — assert the
        // denial fires on the expected check.
        let yaml = r#"
version: "1"
agent: omnibus_demo
binding:
  domain_allowlist: ["api.example.com"]
  tool_denylist: ["shell_exec"]
  daily_budget_usd: 500
  max_single_action_usd: 100
  currency_allowlist: [EUR, USD]
  language_allowlist: [en]
  max_recipients: 10
  cooldown_seconds: 60
"#;
        let p = parse(yaml).expect("parse");
        let c = compile(p).expect("compile");
        let mut a = crate::policy::invariants::Action {
            action_id: "demo".into(),
            tool: "http_post".into(),
            amount_usd: Some(50.0),
            timestamp: 1000,
            ..Default::default()
        };
        // Set all required metadata so we only deny on one check.
        a.metadata
            .insert("target_domain".into(), serde_json::json!("api.example.com"));
        a.metadata
            .insert("currency".into(), serde_json::json!("EUR"));
        a.metadata
            .insert("detected_language".into(), serde_json::json!("en"));
        a.metadata
            .insert("recipient_count".into(), serde_json::json!(5));
        let ctx = make_ctx(&a, 0.0);
        // All declared signals supplied → expect Allow.
        let v = crate::policy::evaluator::evaluate(&c, &ctx);
        assert!(v.is_allow(), "expected Allow, got {v:?}");

        // Flip the per-action cap by raising amount → expect deny on
        // `per_action_cap` (cooldown only fires when last_action_at is
        // set, which we deliberately leave None here).
        let big = crate::policy::invariants::Action {
            amount_usd: Some(101.0),
            ..a.clone()
        };
        let ctx2 = make_ctx(&big, 0.0);
        let (overall, trace) = crate::policy::evaluator::evaluate_with_trace(&c, &ctx2);
        assert!(overall.is_deny());
        match overall {
            Verdict::Deny { check, .. } => assert_eq!(check, "per_action_cap"),
            _ => unreachable!(),
        }
        // Trace records every check (no short-circuit) — proves the
        // dashboard's debugger can still surface a full evaluation.
        assert_eq!(trace.len(), c.checks.len());
    }

    #[test]
    fn dry_run_flag_registers_dry_run_check() {
        let yaml = r#"
version: "1"
agent: dry_run_demo
binding:
  dry_run: true
"#;
        let p = parse(yaml).unwrap();
        let c = compile(p).unwrap();
        assert!(c.checks.iter().any(|c| c.name() == "dry_run"));
    }

    // ----- All 10 fixtures parse + compile without error -----

    #[test]
    fn all_ten_fixtures_compile_without_parse_error() {
        let fixtures: &[(&str, &str)] = &[
            ("banking", FX_BANKING),
            ("minimal", FX_MINIMAL),
            ("healthcare", FX_HEALTHCARE),
            ("devtools", FX_DEVTOOLS),
            ("research", FX_RESEARCH),
            ("support", FX_SUPPORT),
            ("marketing", FX_MARKETING),
            ("legal", FX_LEGAL),
            ("analyst", FX_ANALYST),
            ("treasury", FX_TREASURY),
        ];
        for (name, src) in fixtures {
            let p = parse(src).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
            compile(p).unwrap_or_else(|e| panic!("{name}: compile: {e}"));
        }
    }
}
