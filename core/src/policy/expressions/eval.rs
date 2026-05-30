//! Tree-walking evaluator for parsed invariant expressions.
//!
//! Evaluates an [`Expr`] against an [`EvalEnv`] (action + context + binding
//! constants + clock) and produces a [`Value`]. The wrapper
//! [`eval_predicate`] enforces that the top-level result is a boolean.
//!
//! Identifier resolution and the function whitelist are documented on the
//! individual helpers so future invariants can extend them in one place.

use std::fmt;

use super::parser::{BinOp, Expr, UnaryOp};
use crate::policy::ast::Binding;
use crate::policy::invariants::{Action, EvaluationContext};

/// Runtime value type for the expression evaluator.
///
/// Intentionally small — no maps or first-class functions. `Null` represents
/// "field absent on this action" so policy authors can write
/// `payment_currency in (…)` without crashing when the action doesn't carry
/// that field.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Numeric value (`f64` — handles ints + floats uniformly).
    Num(f64),
    /// String value.
    Str(String),
    /// Boolean value.
    Bool(bool),
    /// List of values (from tuple `(a, b)` or bracket `[a, b]` literals).
    List(Vec<Value>),
    /// Absent value — produced by missing optional fields. Comparisons
    /// against `Null` return [`EvalError::TypeError`].
    Null,
}

impl Value {
    /// Tag for error messages.
    fn tag(&self) -> &'static str {
        match self {
            Value::Num(_) => "Num",
            Value::Str(_) => "Str",
            Value::Bool(_) => "Bool",
            Value::List(_) => "List",
            Value::Null => "Null",
        }
    }
}

/// Read-only environment for one expression evaluation.
///
/// All borrows are immutable — evaluation never mutates the host. The
/// `binding` slot lets invariants reference policy-level constants such as
/// `max_budget_usd` directly by name.
#[derive(Debug)]
pub struct EvalEnv<'a> {
    /// The action under evaluation.
    pub action: &'a Action,
    /// Live context computed by the caller (spend totals, recent calls, …).
    pub ctx: &'a EvaluationContext<'a>,
    /// Policy binding — provides constants like `max_budget_usd`.
    pub binding: &'a Binding,
    /// Wall-clock epoch seconds (matches `ctx.now_epoch` for consistency).
    pub now_epoch: i64,
}

/// Errors raised during evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    /// Identifier didn't resolve to any context/action/binding field.
    UnknownIdent(String),
    /// Function name isn't in the whitelist.
    UnknownFunction(String),
    /// Operator received operands of the wrong types.
    TypeError(String),
    /// Wrong number / shape of arguments to a whitelisted function.
    BadArgs { func: &'static str, msg: String },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::UnknownIdent(n) => write!(f, "unknown identifier '{n}'"),
            EvalError::UnknownFunction(n) => write!(f, "unknown function '{n}'"),
            EvalError::TypeError(m) => write!(f, "type error: {m}"),
            EvalError::BadArgs { func, msg } => write!(f, "bad arguments to {func}: {msg}"),
        }
    }
}

impl std::error::Error for EvalError {}

/// Evaluate `expr` against `env`, returning the resulting [`Value`].
pub fn eval(expr: &Expr, env: &EvalEnv) -> Result<Value, EvalError> {
    match expr {
        Expr::Num(n) => Ok(Value::Num(*n)),
        Expr::Str(s) => Ok(Value::Str(s.clone())),
        Expr::Bool(b) => Ok(Value::Bool(*b)),
        Expr::Ident(name) => resolve_ident(name, env),
        Expr::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(it, env)?);
            }
            Ok(Value::List(out))
        }
        Expr::Binary(op, l, r) => apply_binary(*op, eval(l, env)?, eval(r, env)?),
        Expr::Unary(op, e) => apply_unary(*op, eval(e, env)?),
        Expr::In(lhs, rhs) => {
            let v = eval(lhs, env)?;
            let list = eval(rhs, env)?;
            match list {
                Value::List(items) => {
                    // Null on the LHS means "field not present on this
                    // action" — treat as not-constrained and return true.
                    // SQL-style three-valued logic would return Unknown here;
                    // we collapse to Allow to keep the simple Bool API and
                    // because policy authors expect absent optional fields
                    // to be ignored by membership tests.
                    if matches!(v, Value::Null) {
                        return Ok(Value::Bool(true));
                    }
                    Ok(Value::Bool(items.iter().any(|x| x == &v)))
                }
                other => Err(EvalError::TypeError(format!(
                    "`in` expects List on rhs, got {}",
                    other.tag()
                ))),
            }
        }
        Expr::Call(name, args) => call(name, args, env),
    }
}

/// Evaluate `expr` and require the top-level value to be a `Bool`.
pub fn eval_predicate(expr: &Expr, env: &EvalEnv) -> Result<bool, EvalError> {
    match eval(expr, env)? {
        Value::Bool(b) => Ok(b),
        v => Err(EvalError::TypeError(format!(
            "predicate must be Bool, got {}",
            v.tag()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Identifier resolution
// ---------------------------------------------------------------------------

/// Resolve a bare identifier against the live env.
///
/// Resolution order is documented case-by-case. To extend, add a new match
/// arm here — keep `binding` lookups distinct from `action` so the error
/// messages stay precise.
fn resolve_ident(name: &str, env: &EvalEnv) -> Result<Value, EvalError> {
    match name {
        // Spend totals — both spellings map to the same context field.
        "spend_total" | "spend_total_usd" => Ok(Value::Num(env.ctx.spend_total_usd)),

        // Clock — exposed both as identifier and as `now()` function for
        // ergonomics. Identifier form returns the same epoch number.
        "now" => Ok(Value::Num(env.now_epoch as f64)),

        // Binding constants. Absent → Null so `cmp` can produce a clean type
        // error instead of a silent UnknownIdent.
        "max_budget_usd" => Ok(env
            .binding
            .max_budget_usd
            .map(Value::Num)
            .unwrap_or(Value::Null)),

        // Action fields — bare + dotted spellings both resolve.
        "tool" | "action.tool" => Ok(Value::Str(env.action.tool.clone())),
        "amount_usd" | "action.amount_usd" => Ok(env
            .action
            .amount_usd
            .map(Value::Num)
            .unwrap_or(Value::Null)),
        "data_classification" | "action.data_classification" => Ok(env
            .action
            .data_classification
            .clone()
            .map(Value::Str)
            .unwrap_or(Value::Null)),
        "action.signatures" | "signatures" => Ok(Value::List(
            env.action
                .signatures
                .iter()
                .cloned()
                .map(Value::Str)
                .collect(),
        )),
        "delegation_depth" | "action.delegation_depth" => {
            Ok(Value::Num(env.action.delegation_depth as f64))
        }
        "timestamp" | "action.timestamp" => Ok(Value::Num(env.action.timestamp as f64)),

        // Action lacks a structured `metadata.payment_currency` field today;
        // explicit Null lets `payment_currency in (…)` produce a TypeError
        // rather than UnknownIdent. The dashboard surfaces that cleanly.
        "payment_currency" => Ok(Value::Null),

        _ => Err(EvalError::UnknownIdent(name.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

fn apply_binary(op: BinOp, l: Value, r: Value) -> Result<Value, EvalError> {
    match op {
        BinOp::Eq => eq_neq(l, r, false),
        BinOp::Neq => eq_neq(l, r, true),
        BinOp::Lt | BinOp::Lte | BinOp::Gt | BinOp::Gte => num_cmp(op, l, r),
        BinOp::Add | BinOp::Sub => num_arith(op, l, r),
        BinOp::And => bool_bin(op, l, r),
        BinOp::Or => bool_bin(op, l, r),
    }
}

fn eq_neq(l: Value, r: Value, negate: bool) -> Result<Value, EvalError> {
    let eq = match (&l, &r) {
        (Value::Num(a), Value::Num(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Null, Value::Null) => true,
        // Mixed-type equality is a hard error — prevents the
        // `'EUR' == 1` foot-gun policy authors will inevitably try.
        _ => {
            return Err(EvalError::TypeError(format!(
                "cannot compare {} and {} with ==/!=",
                l.tag(),
                r.tag()
            )))
        }
    };
    Ok(Value::Bool(if negate { !eq } else { eq }))
}

fn num_cmp(op: BinOp, l: Value, r: Value) -> Result<Value, EvalError> {
    let (a, b) = match (&l, &r) {
        (Value::Num(a), Value::Num(b)) => (*a, *b),
        _ => {
            return Err(EvalError::TypeError(format!(
                "{:?} expects two Num, got {} and {}",
                op,
                l.tag(),
                r.tag()
            )))
        }
    };
    // Fail closed on non-finite operands. IEEE-754 makes every comparison
    // against NaN return `false`, so `NaN > max_budget` and
    // `NaN <= max_budget` both evaluate to `false` — which can flip a deny
    // into an allow (or vice-versa) depending on how the policy is phrased.
    // A non-finite value never has a defensible ordering, so we refuse to
    // compare it; the caller (ExpressionCheck) maps the error to a Deny.
    if !a.is_finite() || !b.is_finite() {
        return Err(EvalError::TypeError(format!(
            "{op:?} on non-finite number ({a} vs {b}) — refusing to order (fail-closed)"
        )));
    }
    Ok(Value::Bool(match op {
        BinOp::Lt => a < b,
        BinOp::Lte => a <= b,
        BinOp::Gt => a > b,
        BinOp::Gte => a >= b,
        _ => unreachable!("num_cmp called with non-cmp op"),
    }))
}

fn num_arith(op: BinOp, l: Value, r: Value) -> Result<Value, EvalError> {
    let (a, b) = match (&l, &r) {
        (Value::Num(a), Value::Num(b)) => (*a, *b),
        _ => {
            return Err(EvalError::TypeError(format!(
                "{:?} expects two Num, got {} and {}",
                op,
                l.tag(),
                r.tag()
            )))
        }
    };
    if !a.is_finite() || !b.is_finite() {
        return Err(EvalError::TypeError(format!(
            "{op:?} on non-finite number ({a} vs {b}) — refusing to compute (fail-closed)"
        )));
    }
    let out = match op {
        BinOp::Add => a + b,
        BinOp::Sub => a - b,
        _ => unreachable!("num_arith called with non-arith op"),
    };
    // Overflow to ±inf would silently re-enter a comparison and corrupt the
    // verdict; surface it as an error instead.
    if !out.is_finite() {
        return Err(EvalError::TypeError(format!(
            "{op:?} produced non-finite result ({out}) — refusing (fail-closed)"
        )));
    }
    Ok(Value::Num(out))
}

fn bool_bin(op: BinOp, l: Value, r: Value) -> Result<Value, EvalError> {
    let (a, b) = match (&l, &r) {
        (Value::Bool(a), Value::Bool(b)) => (*a, *b),
        _ => {
            return Err(EvalError::TypeError(format!(
                "{:?} expects two Bool, got {} and {}",
                op,
                l.tag(),
                r.tag()
            )))
        }
    };
    Ok(Value::Bool(match op {
        BinOp::And => a && b,
        BinOp::Or => a || b,
        _ => unreachable!("bool_bin called with non-bool op"),
    }))
}

fn apply_unary(op: UnaryOp, v: Value) -> Result<Value, EvalError> {
    match (op, v) {
        (UnaryOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
        (UnaryOp::Not, other) => Err(EvalError::TypeError(format!(
            "`!` expects Bool, got {}",
            other.tag()
        ))),
        (UnaryOp::Neg, Value::Num(n)) => Ok(Value::Num(-n)),
        (UnaryOp::Neg, other) => Err(EvalError::TypeError(format!(
            "unary `-` expects Num, got {}",
            other.tag()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Function whitelist
// ---------------------------------------------------------------------------

/// Resolve a call argument by keyword name, falling back to positional
/// index, then evaluate it. Keyword args (`role: 'x'`) win over positional.
fn arg_value(
    func: &'static str,
    keyword: &str,
    pos: usize,
    args: &[(Option<String>, Expr)],
    env: &EvalEnv,
) -> Result<Value, EvalError> {
    if let Some((_, e)) = args.iter().find(|(k, _)| k.as_deref() == Some(keyword)) {
        return eval(e, env);
    }
    if let Some((k, e)) = args.get(pos) {
        if k.is_none() {
            return eval(e, env);
        }
    }
    Err(EvalError::BadArgs {
        func,
        msg: format!("missing argument '{keyword}'"),
    })
}

fn want_str(func: &'static str, v: Value) -> Result<String, EvalError> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(EvalError::BadArgs {
            func,
            msg: format!("expected Str, got {}", other.tag()),
        }),
    }
}

fn want_num(func: &'static str, v: Value) -> Result<f64, EvalError> {
    match v {
        Value::Num(n) if n.is_finite() => Ok(n),
        Value::Num(_) => Err(EvalError::BadArgs {
            func,
            msg: "expected finite Num".into(),
        }),
        other => Err(EvalError::BadArgs {
            func,
            msg: format!("expected Num, got {}", other.tag()),
        }),
    }
}

fn want_str_list(func: &'static str, v: Value) -> Result<Vec<String>, EvalError> {
    match v {
        Value::List(items) => items
            .into_iter()
            .map(|it| want_str(func, it))
            .collect::<Result<Vec<_>, _>>(),
        other => Err(EvalError::BadArgs {
            func,
            msg: format!("expected List, got {}", other.tag()),
        }),
    }
}

/// Dispatch a function call. Whitelist is documented per arm.
fn call(name: &str, args: &[(Option<String>, Expr)], env: &EvalEnv) -> Result<Value, EvalError> {
    match name {
        // now() — current wall-clock epoch seconds as Num.
        "now" => {
            require_arity("now", args, 0)?;
            Ok(Value::Num(env.now_epoch as f64))
        }

        // len(s: Str) — string length in chars.
        "len" => {
            require_arity("len", args, 1)?;
            match eval(&args[0].1, env)? {
                Value::Str(s) => Ok(Value::Num(s.chars().count() as f64)),
                other => Err(EvalError::BadArgs {
                    func: "len",
                    msg: format!("expected Str, got {}", other.tag()),
                }),
            }
        }

        // count(list: List) — list length.
        "count" => {
            require_arity("count", args, 1)?;
            match eval(&args[0].1, env)? {
                Value::List(items) => Ok(Value::Num(items.len() as f64)),
                other => Err(EvalError::BadArgs {
                    func: "count",
                    msg: format!("expected List, got {}", other.tag()),
                }),
            }
        }

        // no_external_call_to(domain: STR) — true iff the action does NOT
        // target the named domain. Reads the agent-declared `target_domain`
        // metadata key (same key as DomainAllowlistCheck). A missing key
        // means the action declares no external target, so the constraint
        // is satisfied.
        "no_external_call_to" => {
            require_arity("no_external_call_to", args, 1)?;
            let domain = want_str(
                "no_external_call_to",
                arg_value("no_external_call_to", "domain", 0, args, env)?,
            )?;
            let target = env
                .action
                .metadata
                .get("target_domain")
                .and_then(|v| v.as_str());
            Ok(Value::Bool(target != Some(domain.as_str())))
        }

        // transfer_requires(roles: LIST<STR>) — every listed role must be
        // present in the action's `signatures` before a money-moving action
        // (amount_usd present) is allowed. Non-transfer actions are exempt.
        "transfer_requires" => {
            require_arity("transfer_requires", args, 1)?;
            let roles = want_str_list(
                "transfer_requires",
                arg_value("transfer_requires", "roles", 0, args, env)?,
            )?;
            if env.action.amount_usd.is_none() {
                return Ok(Value::Bool(true));
            }
            let sigs = &env.action.signatures;
            let satisfied = roles.iter().all(|r| sigs.iter().any(|s| s == r));
            Ok(Value::Bool(satisfied))
        }

        // exports_require_signatures(role: STR, threshold: NUM) — the action
        // must carry at least `threshold` signatures from `role`. Like
        // SignatureCheck this counts role occurrences; the caller is
        // responsible for distinct-signer deduplication upstream.
        "exports_require_signatures" => {
            require_arity("exports_require_signatures", args, 2)?;
            let role = want_str(
                "exports_require_signatures",
                arg_value("exports_require_signatures", "role", 0, args, env)?,
            )?;
            let threshold = want_num(
                "exports_require_signatures",
                arg_value("exports_require_signatures", "threshold", 1, args, env)?,
            )?;
            if threshold < 0.0 {
                return Err(EvalError::BadArgs {
                    func: "exports_require_signatures",
                    msg: "threshold must be >= 0".into(),
                });
            }
            // Distinct-signer count — same contract as SignatureCheck, so
            // `["clinician","clinician"]` cannot satisfy a 2-signature gate.
            let got = crate::policy::invariants::signature::distinct_role_signatures(
                &env.action.signatures,
                &role,
            );
            Ok(Value::Bool(got as f64 >= threshold))
        }

        // tool_class(tool) — returns the agent-declared class of the tool as
        // a Str (from the `tool_class` metadata key), defaulting to
        // "unknown". Used as `tool_class(tool) == 'read_only'`. The argument
        // is evaluated for type-checking but the class comes from metadata so
        // the agent cannot launder a tool's class through the argument.
        "tool_class" => {
            require_arity("tool_class", args, 1)?;
            let _ = arg_value("tool_class", "tool", 0, args, env)?;
            let class = env
                .action
                .metadata
                .get("tool_class")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(Value::Str(class.to_string()))
        }

        // sandbox_required(tool: STR) — if the action invokes the named tool
        // it must declare `sandbox_mode == true` in metadata; otherwise the
        // constraint does not apply and the action is allowed.
        "sandbox_required" => {
            require_arity("sandbox_required", args, 1)?;
            let tool = want_str(
                "sandbox_required",
                arg_value("sandbox_required", "tool", 0, args, env)?,
            )?;
            if env.action.tool != tool {
                return Ok(Value::Bool(true));
            }
            let sandboxed = env
                .action
                .metadata
                .get("sandbox_mode")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Value::Bool(sandboxed))
        }

        _ => Err(EvalError::UnknownFunction(name.to_string())),
    }
}

fn require_arity(
    func: &'static str,
    args: &[(Option<String>, Expr)],
    want: usize,
) -> Result<(), EvalError> {
    if args.len() != want {
        return Err(EvalError::BadArgs {
            func,
            msg: format!("expected {want} args, got {}", args.len()),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ast::Binding;
    use crate::policy::expressions::parser::parse;

    fn mk_action() -> Action {
        Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(100.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into(), "cfo".into()],
            delegation_depth: 2,
            timestamp: 1_700_000_000,
            ..Default::default()
        }
    }

    fn mk_binding() -> Binding {
        Binding {
            max_budget_usd: Some(5000.0),
            ..Default::default()
        }
    }

    struct Holder {
        action: Action,
        binding: Binding,
    }

    fn with_env<F: FnOnce(&EvalEnv)>(spend: f64, f: F) {
        let h = Holder {
            action: mk_action(),
            binding: mk_binding(),
        };
        let mut ctx = EvaluationContext::with_defaults(&h.action);
        ctx.spend_total_usd = spend;
        ctx.now_epoch = 1_700_000_500;
        ctx.now_tz_hhmm = "12:00".to_string();
        let env = EvalEnv {
            action: &h.action,
            ctx: &ctx,
            binding: &h.binding,
            now_epoch: 1_700_000_500,
        };
        f(&env);
    }

    fn eval_str(input: &str, env: &EvalEnv) -> Result<Value, EvalError> {
        let e = parse(input).expect("parse");
        eval(&e, env)
    }

    fn pred(input: &str, env: &EvalEnv) -> bool {
        let e = parse(input).expect("parse");
        eval_predicate(&e, env).expect("eval predicate")
    }

    // ----- identifier resolution -----

    #[test]
    fn resolves_spend_total() {
        with_env(123.0, |env| {
            assert_eq!(eval_str("spend_total", env).unwrap(), Value::Num(123.0));
            assert_eq!(eval_str("spend_total_usd", env).unwrap(), Value::Num(123.0));
        });
    }

    #[test]
    fn resolves_max_budget_usd_from_binding() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("max_budget_usd", env).unwrap(), Value::Num(5000.0));
        });
    }

    #[test]
    fn resolves_max_budget_usd_absent_as_null() {
        let action = mk_action();
        let binding = Binding::default();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv {
            action: &action,
            ctx: &ctx,
            binding: &binding,
            now_epoch: 0,
        };
        assert_eq!(eval_str("max_budget_usd", &env).unwrap(), Value::Null);
    }

    #[test]
    fn resolves_now_identifier_and_function() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("now", env).unwrap(), Value::Num(1_700_000_500.0));
            assert_eq!(eval_str("now()", env).unwrap(), Value::Num(1_700_000_500.0));
        });
    }

    #[test]
    fn resolves_action_fields_bare_and_dotted() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("tool", env).unwrap(), Value::Str("sepa_payment_initiate".into()));
            assert_eq!(eval_str("action.tool", env).unwrap(), Value::Str("sepa_payment_initiate".into()));
            assert_eq!(eval_str("amount_usd", env).unwrap(), Value::Num(100.0));
            assert_eq!(eval_str("delegation_depth", env).unwrap(), Value::Num(2.0));
            assert_eq!(eval_str("timestamp", env).unwrap(), Value::Num(1_700_000_000.0));
            assert_eq!(
                eval_str("data_classification", env).unwrap(),
                Value::Str("financial".into())
            );
            let sigs = eval_str("signatures", env).unwrap();
            assert_eq!(
                sigs,
                Value::List(vec![Value::Str("human_approver".into()), Value::Str("cfo".into())])
            );
        });
    }

    #[test]
    fn payment_currency_is_null_today() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("payment_currency", env).unwrap(), Value::Null);
        });
    }

    #[test]
    fn unknown_ident_errors() {
        with_env(0.0, |env| {
            let err = eval_str("definitely_not_a_field", env).unwrap_err();
            assert!(matches!(err, EvalError::UnknownIdent(_)));
        });
    }

    // ----- comparisons -----

    #[test]
    fn num_comparisons() {
        with_env(100.0, |env| {
            assert!(pred("spend_total <= max_budget_usd", env));
            assert!(pred("spend_total < 1000", env));
            assert!(pred("spend_total == 100", env));
            assert!(!pred("spend_total > 1000", env));
            assert!(pred("spend_total >= 100", env));
            assert!(pred("spend_total != 0", env));
        });
    }

    #[test]
    fn str_equality() {
        with_env(0.0, |env| {
            assert!(pred("data_classification == 'financial'", env));
            assert!(pred("data_classification != 'restricted'", env));
        });
    }

    #[test]
    fn bool_equality() {
        with_env(0.0, |env| {
            assert!(pred("true == true", env));
            assert!(pred("true != false", env));
        });
    }

    #[test]
    fn mixed_type_equality_is_type_error() {
        with_env(0.0, |env| {
            let e = parse("'EUR' == 1").unwrap();
            let err = eval(&e, env).unwrap_err();
            assert!(matches!(err, EvalError::TypeError(_)));
        });
    }

    #[test]
    fn num_arithmetic() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("1 + 2", env).unwrap(), Value::Num(3.0));
            assert_eq!(eval_str("5 - 3", env).unwrap(), Value::Num(2.0));
            assert_eq!(eval_str("-4 + 1", env).unwrap(), Value::Num(-3.0));
        });
    }

    #[test]
    fn arithmetic_type_error() {
        with_env(0.0, |env| {
            let e = parse("'a' + 1").unwrap();
            assert!(matches!(eval(&e, env).unwrap_err(), EvalError::TypeError(_)));
        });
    }

    // ----- boolean operators -----

    #[test]
    fn bool_and_or_not() {
        with_env(0.0, |env| {
            assert!(pred("true && true", env));
            assert!(!pred("true && false", env));
            assert!(pred("false || true", env));
            assert!(!pred("!true", env));
            assert!(pred("not false", env));
        });
    }

    #[test]
    fn unary_neg_on_non_num_errors() {
        with_env(0.0, |env| {
            let e = parse("-true").unwrap();
            assert!(matches!(eval(&e, env).unwrap_err(), EvalError::TypeError(_)));
        });
    }

    // ----- `in` membership -----

    #[test]
    fn in_membership_str_tuple() {
        with_env(0.0, |env| {
            // payment_currency is Null today — Null-in-list collapses to
            // Bool(true) so absent fields don't accidentally deny.
            assert!(pred("payment_currency in ('EUR', 'USD')", env));
            // Direct literal works.
            assert!(pred("'EUR' in ('EUR', 'USD')", env));
            assert!(!pred("'GBP' in ('EUR', 'USD')", env));
        });
    }

    #[test]
    fn in_membership_bracket_list() {
        with_env(0.0, |env| {
            assert!(pred("1 in [1, 2, 3]", env));
            assert!(!pred("4 in [1, 2, 3]", env));
        });
    }

    // ----- functions -----

    #[test]
    fn len_function_returns_char_count() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("len('abcd')", env).unwrap(), Value::Num(4.0));
        });
    }

    #[test]
    fn count_function_on_signatures() {
        with_env(0.0, |env| {
            assert_eq!(eval_str("count(signatures)", env).unwrap(), Value::Num(2.0));
        });
    }

    #[test]
    fn no_external_call_to_allows_when_target_absent_or_different() {
        // mk_action() carries no target_domain metadata → constraint met.
        with_env(0.0, |env| {
            assert!(pred("no_external_call_to(domain: 'competitor.com')", env));
        });
    }

    #[test]
    fn no_external_call_to_denies_matching_target() {
        let mut action = mk_action();
        action
            .metadata
            .insert("target_domain".into(), serde_json::json!("competitor.com"));
        let binding = mk_binding();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        assert!(!pred("no_external_call_to(domain: 'competitor.com')", &env));
        assert!(pred("no_external_call_to(domain: 'partner.com')", &env));
    }

    #[test]
    fn transfer_requires_enforces_roles_on_money_moves() {
        // mk_action() has amount_usd=Some and signatures=[human_approver, cfo].
        with_env(0.0, |env| {
            assert!(pred("transfer_requires(roles: ['human_approver', 'cfo'])", env));
            // Missing 'treasury_officer' signature on a money-moving action.
            assert!(!pred("transfer_requires(roles: ['treasury_officer'])", env));
        });
    }

    #[test]
    fn transfer_requires_exempts_non_money_actions() {
        let mut action = mk_action();
        action.amount_usd = None;
        action.signatures.clear();
        let binding = mk_binding();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        assert!(pred("transfer_requires(roles: ['cfo'])", &env));
    }

    #[test]
    fn exports_require_signatures_counts_distinct_signers() {
        let mut action = mk_action();
        // Two distinct clinician identities → meets threshold 2, not 3.
        action.signatures = vec!["clinician:alice".into(), "clinician:bob".into()];
        let binding = mk_binding();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        assert!(pred("exports_require_signatures(role: 'clinician', threshold: 2)", &env));
        assert!(!pred("exports_require_signatures(role: 'clinician', threshold: 3)", &env));
    }

    #[test]
    fn exports_require_signatures_rejects_duplicate_string() {
        let mut action = mk_action();
        action.signatures = vec!["clinician".into(), "clinician".into()];
        let binding = mk_binding();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        // One distinct signer → cannot meet threshold 2.
        assert!(!pred("exports_require_signatures(role: 'clinician', threshold: 2)", &env));
    }

    #[test]
    fn tool_class_reads_metadata_default_unknown() {
        with_env(0.0, |env| {
            // No tool_class metadata on mk_action() → "unknown".
            assert!(pred("tool_class(tool) == 'unknown'", env));
        });
        let mut action = mk_action();
        action
            .metadata
            .insert("tool_class".into(), serde_json::json!("read_only"));
        let binding = mk_binding();
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        assert!(pred("tool_class(tool) == 'read_only'", &env));
    }

    #[test]
    fn sandbox_required_gates_named_tool() {
        let mut action = mk_action();
        action.tool = "run_sandboxed".into();
        let binding = mk_binding();
        // sandbox_mode absent → denied.
        {
            let ctx = EvaluationContext::with_defaults(&action);
            let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
            assert!(!pred("sandbox_required(tool: 'run_sandboxed')", &env));
        }
        // sandbox_mode=true → allowed.
        action
            .metadata
            .insert("sandbox_mode".into(), serde_json::json!(true));
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        assert!(pred("sandbox_required(tool: 'run_sandboxed')", &env));
    }

    #[test]
    fn nan_comparison_is_fail_closed() {
        let action = mk_action();
        let mut binding = mk_binding();
        binding.max_budget_usd = Some(f64::NAN);
        let ctx = EvaluationContext::with_defaults(&action);
        let env = EvalEnv { action: &action, ctx: &ctx, binding: &binding, now_epoch: 0 };
        // IEEE would make `100 > NaN` == false (silently allow); we error instead.
        let err = eval_str("amount_usd > max_budget_usd", &env).unwrap_err();
        assert!(matches!(err, EvalError::TypeError(_)), "{err:?}");
    }

    #[test]
    fn unknown_function_errors() {
        with_env(0.0, |env| {
            let e = parse("totally_made_up_fn()").unwrap();
            assert!(matches!(eval(&e, env).unwrap_err(), EvalError::UnknownFunction(_)));
        });
    }

    #[test]
    fn arity_mismatch_errors() {
        with_env(0.0, |env| {
            let e = parse("len('a', 'b')").unwrap();
            assert!(matches!(eval(&e, env).unwrap_err(), EvalError::BadArgs { .. }));
        });
    }

    #[test]
    fn eval_predicate_rejects_non_bool() {
        with_env(0.0, |env| {
            let e = parse("1 + 2").unwrap();
            assert!(matches!(eval_predicate(&e, env).unwrap_err(), EvalError::TypeError(_)));
        });
    }

    #[test]
    fn complex_compound_predicate() {
        with_env(100.0, |env| {
            // (spend < max && data != 'restricted') || false
            assert!(pred(
                "(spend_total < max_budget_usd && data_classification != 'restricted') || false",
                env
            ));
        });
    }
}
